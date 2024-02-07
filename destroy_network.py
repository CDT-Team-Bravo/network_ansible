import subprocess
import asyncio
import os

from time import sleep

async def run(cmd: str, cwd=os.getcwd()) -> tuple[str | None, str | None]:
    """
    Asyncronously start a subprocess and run a command returning its output
    """
    proc = await asyncio.create_subprocess_shell(
        cmd,
        cwd=cwd,
        stderr=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        env=os.environ.copy()
    )

    stdout, stderr = await proc.communicate()
    return stdout.decode().strip() if stdout else None, stderr.decode().strip() if stderr else None


async def delete_network_by_name(net_name):
    res, err = await run(f'openstack network delete "{net_name}"')
    if err is not None and 'No Network found' in err:
        return None, None
    if err is not None and 'these ports is' in err:
        port_ids = err.split('id for these ports is: ', 1)[-1].split('.\n', 1)[0].split(' ')
        for port_id in port_ids:
            sub_res, sub_err = await run(f'openstack port delete {port_id[:36]}')
            if sub_err is not None:
                raise Exception(sub_err)
        res, err = await run(f'openstack network delete "{net_name}"')
    print(net_name, f'Network({res}, {err})')


async def delete_networks_by_names(net_names):
    tasks = []
    names, _ = await run('openstack network list -f value -c Name')
    names = names.split('\n')
    for net_name in set(net_names) & set(names):
        task = asyncio.ensure_future(delete_network_by_name(net_name))
        tasks.append(task)
    await asyncio.gather(*tasks)


async def delete_instance(name, id):
    volume_id, _ = await run(f'openstack server show {id}  -f json -c volumes_attached | grep -oP \'"id": "\K[^"]+\' | head -1')
    res, err = await run(f'openstack server delete {id}')
    print(name, f'Server({res}, {err})')
    return name, volume_id


async def delete_volume(name, id):
    res, err = await run(f'openstack volume delete {id}')
    err_count = 0
    while err is not None and 'volume status must be available' in err.lower():
        err_count += 1
        sleep(1)
        res, err = await run(f'openstack volume delete {id}')
    print(name, f'Volume({res}, {err}, {err_count})')
    

async def delete_pf_instances():
    ids, _ = await run('openstack server list -f value -c ID')
    ids = ids.split('\n')
    names, _ = await run('openstack server list -f value -c Name')
    names = names.split('\n')
    delete_instance_tasks = []
    for instance_id, name in zip(ids, names):
        if name.strip().lower().endswith('_pfsense'):
            task = asyncio.ensure_future(delete_instance(name, instance_id))
            delete_instance_tasks.append(task)
    volume_ids = await asyncio.gather(*delete_instance_tasks)
    delete_volume_tasks = []
    for name, volume_id in volume_ids:
        task = asyncio.ensure_future(delete_volume(name, volume_id))
        delete_volume_tasks.append(task)
    await asyncio.gather(*delete_volume_tasks)
    

async def main():
    await delete_pf_instances()

    net_names = ['red_net', 'local_1_net', 'remote_1_net', 'sat_1_net', 'local_2_net', 'remote_2_net', 'sat_2_net']
    await delete_networks_by_names(net_names)


if __name__ == '__main__':
    asyncio.run(main())
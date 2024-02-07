import subprocess
import asyncio
import os

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
    return res, err


async def delete_networks_by_names(net_names):
    tasks = []
    for net_name in net_names:
        task = asyncio.ensure_future(delete_network_by_name(net_name))
        tasks.append(task)
    await asyncio.gather(*tasks)


async def delete_pf_instances():
    ids, _ = await run('openstack server list -f value -c ID')
    ids = ids.split('\n')
    names, _ = await run('openstack server list -f value -c Name')
    names = names.split('\n')
    for instance_id, name in zip(ids, names):
        if name.strip().lower().endswith('_pfsense'):
            volume_id, _ = await run(f'openstack server show {instance_id}  -f json -c volumes_attached | grep -oP \'"id": "\K[^"]+\' | head -1')
            s_res, s_err = await run(f'openstack server delete {instance_id}')
            v_res, v_err = await run(f'openstack volume delete {volume_id}')
            print(name, f'Server({s_res}, {s_err})', f'Volume({v_res}, {v_err})')
    

async def main():
    # res, err = await openstack_auth()
    # print(res, err)
    # net_names = ['red_net', 'local_1_net', 'remote_1_net', 'sat_1_net', 'local_2_net', 'remote_2_net', 'sat_2_net']
    # for net_name in net_names:
    #     res, err = await delete_network_by_name(net_name)
    #     print(net_name, res, err)
    await delete_pf_instances()


if __name__ == '__main__':
    asyncio.run(main())
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
    print(net_name, f'Network({res=}, {err=})')


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
    print(name, f'Server({res=}, {err=})')
    return name, volume_id


async def delete_volume(name, id):
    res, err = await run(f'openstack volume delete {id}')
    err_count = 0
    while err is not None and 'volume status must be available' in err.lower():
        err_count += 1
        sleep(1)
        res, err = await run(f'openstack volume delete {id}')
    print(name, f'Volume({res=}, {err=}, {err_count})')
    

async def delete_unassigned_volumes():
    volume_info, err = await run('openstack volume list -f value -c ID -c Status -c "Attached to"')
    if err:
        raise Exception(err)
    volume_info = volume_info.split('\n')
    delete_volume_tasks = []
    for volume in volume_info:
        volume_id, status, attached_to = volume.split(' ', 2)
        if status == 'available' and len(attached_to) == 2:
            delete_volume_task = asyncio.ensure_future(delete_volume(None, volume_id))
            delete_volume_tasks.append(delete_volume_task)
    await asyncio.gather(*delete_volume_tasks)


async def delete_instances_by_suffix(suffix: str):
    ids, err = await run('openstack server list -f value -c ID')
    if err:
        raise Exception(err)
    ids = ids.split('\n')
    names, _ = await run('openstack server list -f value -c Name')
    names = names.split('\n')
    delete_instance_tasks = []
    for instance_id, name in zip(ids, names):
        if name.strip().lower().endswith(suffix):
            task = asyncio.ensure_future(delete_instance(name, instance_id))
            delete_instance_tasks.append(task)
    volume_ids = await asyncio.gather(*delete_instance_tasks)
    delete_volume_tasks = []
    for name, volume_id in volume_ids:
        task = asyncio.ensure_future(delete_volume(name, volume_id))
        delete_volume_tasks.append(task)
    await asyncio.gather(*delete_volume_tasks)
    
async def delete_instances_by_names(instance_names: list):
    ids, err = await run('openstack server list -f value -c ID')
    if err:
        raise Exception(err)
    ids = ids.split('\n')
    names, err = await run('openstack server list -f value -c Name')
    if err:
        raise Exception(err)
    names = names.split('\n')
    delete_instance_tasks = []
    for instance_id, name in zip(ids, names):
        if name.strip() in instance_names:
            task = asyncio.ensure_future(delete_instance(name, instance_id))
            delete_instance_tasks.append(task)
    volume_ids = await asyncio.gather(*delete_instance_tasks)
    delete_volume_tasks = []
    for name, volume_id in volume_ids:
        task = asyncio.ensure_future(delete_volume(name, volume_id))
        delete_volume_tasks.append(task)
    await asyncio.gather(*delete_volume_tasks)


async def delete_router(name, router_id):
    res, err = await run(f'openstack router delete {router_id}')
    if err is not None and 'No Router found' in err:
        return None, None
    if err is not None and 'has ports still attached' in err:
        port_ids = err.split('has ports still attached: ', 1)[-1].split('.\n', 1)[0].split(' ')
        for port_id in port_ids:
            sub_res, sub_err = await run(f'openstack port delete {port_id[:36]}')
            if sub_err is not None:
                raise Exception(sub_err)
        res, err = await run(f'openstack router delete "{router_id}"')
    print(name, f'Router({res=}, {err=})')


async def delete_routers_by_names(router_names: list):
    ids, err = await run('openstack router list -f value -c ID')
    if err:
        raise Exception(err)
    ids = ids.split('\n')
    names, err = await run('openstack router list -f value -c Name')
    if err:
        raise Exception(err)
    names = names.split('\n')
    delete_router_tasks = []
    for router_id, name in zip(ids, names):
        if name.strip() in router_names:
            task = asyncio.ensure_future(delete_router(name, router_id))
            delete_router_tasks.append(task)
    await asyncio.gather(*delete_router_tasks)


async def main():
    # await delete_pf_instances(suffix='_pfsense')

    # pfsense_names = ['Apollo', 'Artemis', 'Saturn', 'Uranus', 'testbox']
    # testbox_names = ['testbox']
    satellite_tests = ['blue1_NOS3', 'blue2_NOS3', 'blue1_COSMOS', 'blue2_COSMOS']
    await delete_instances_by_names(satellite_tests)

    await delete_unassigned_volumes()

    # openstack_router_names = ['rustdesk_openstack']
    # await delete_routers_by_names(openstack_router_names)

    # rustdesk_net = ['rustdesk_net']
    # red_net = ['red_net']
    # t1_nets = ['local_1_net', 'remote_1_net', 'sat_1_net']
    # t2_nets = ['local_2_net', 'remote_2_net', 'sat_2_net']
    # net_names = t2_nets + t1_nets + red_net + rustdesk_net
    # await delete_networks_by_names(net_names)


if __name__ == '__main__':
    asyncio.run(main())
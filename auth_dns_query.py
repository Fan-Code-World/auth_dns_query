#!/usr/bin/python
# -*- coding: UTF-8 -*-
import commands, sys
import json
import os
import datetime
import time
import re

class Checkout:
    def loger(self, information, status):
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        content = now + information + status
        print (content)
        if status == ' succeed':
            f = file('succeed.log', 'a')
            f.write(content + '\n')
            f.close()
        else:
            f = file('error.log', 'a')
            f.write(content + '\n')
            f.close()

    def checkip(self,ip):
        p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        if p.match(ip):
            pass
        else:
            print("Ip Address format error!!!")
            sys.exit()

    def Special_format_record(self, record):
        a_record = ' '.join(record.split()[4:])
        a_record = a_record.replace('"','') #部分txt类型带"
        a_record = a_record.replace('\\','') #部分txt带\
        return a_record

    #zone file formating  dict
    def analyzone(self, PATH, filename):
        record_dic = {}

        #f = file('abchina.com.txt', 'r') 
        f = file(PATH + filename, 'r') 
        listname = f.readlines()

        for i in listname:
            q_name = i.split()[0].strip()   # q_name
            if len(q_name.split('.')) - len(filename.split('.')) >= 2 :
                continue

            q_type = i.split()[3].strip()   # q_type
            if q_type == 'MX' or q_type == 'TXT' or q_type == 'SOA':
                a_record = self.Special_format_record(i)
            else:
                a_record = i.split()[4].strip().replace('"','')   # Authority records 

            list_gtm_domain = []
            for i in a_record.split(':'):
                list_gtm_domain.append(i.lstrip('0').lower())
                simple_v6ip = ':'.join(list_gtm_domain)
                a_record = simple_v6ip

            if record_dic.has_key(q_name):
                pass
            else:
                record_dic[q_name]={}
        
            if record_dic[q_name].has_key(q_type):
                record_dic[q_name][q_type].append(a_record)
            else:    
                record_dic[q_name][q_type]=[]
                record_dic[q_name][q_type].append(a_record)
        return (record_dic)


    def query(self,record_dic):
        record_dic2 = {}
        #response formating dict
        for q_name in record_dic:  #遍历每个域名
            time.sleep(0.1)
            for q_type in record_dic[q_name].keys():  #遍历每个域名的记录类型
                #if q_type == 'soa' or q_type == 'mx':
                #   continue
                
                #权威服务器响应，+short无法得到权威字段结果,通过answer和authority控制
                list_dns = commands.getoutput('dig +norecurse +nocmd +noall +answer \
                    +ttlid @%s  %s  %s '%(check_dnsip, q_name, q_type)).split('\n')
                if len(list_dns[0]) == 0:
                    list_dns = commands.getoutput('dig +norecurse +nocmd +noall +answer \
                        +authority  +ttlid  @%s  %s  %s '%(check_dnsip, q_name, q_type)).split('\n')
                #可能出现指定的权威服务器没有相关记录
                if len(list_dns[0]) == 0:
                    self.loger('%s in %s Parse failure !!!\n'%(q_name,q_type), 'This domain name cannot be resolved \n')
                    continue
 
                #分析response并放入字典
                for n in list_dns:
                    if q_type == 'MX' or q_type == 'TXT' or q_type == 'SOA':
                        res_type = n.split()[3]
                        #a_record = ' '.join(n.split()[4:])
                        #a_record = a_record.replace('"','') #部分txt类型带"
                        #a_record = a_record.replace('\\','') #部分txt带\
                        a_record = self.Special_format_record(n)
                        a_record = a_record.lower() #dmarc自动应答大写
                    else: 
                        res_type = n.split()[3].strip()   # res_type
                        a_record = n.split()[4].strip()   # Authority records 
                    
                    if 'timed out' in list_dns[0]:
                        a_record = 'Server connection timeout!!!'
                    if res_type != q_type and res_type == 'SOA' :
                        a_record = 'no record'                       
                        #a_record = 'NXDOMIAN'                       

                    if record_dic2.has_key(q_name): 
                        pass
                    else:
                        record_dic2[q_name]={}
                
                    if record_dic2[q_name].has_key(q_type):
                        record_dic2[q_name][q_type].append(a_record)
                    else:
                        record_dic2[q_name][q_type]=[]
                        record_dic2[q_name][q_type].append(a_record)

                if set(record_dic[q_name][q_type]) == set(record_dic2[q_name][q_type]):
                    self.loger(' %s in %s :'%(q_name, q_type ), ' succeed')
                else:
                    self.loger(' %s in %s : error!!!\n'%(q_name, q_type),
                        'zone_file: %s in %s :%s \nresponese: %s in %s :%s\n'%(
                            q_name, q_type, record_dic[q_name][q_type], 
                                q_name, q_type, record_dic2[q_name][q_type]))

if __name__ == '__main__':
    t = Checkout()
    check_dnsip = raw_input('\33[1;32mPlease enter the service IP address to be \
detected:\33[0m').strip()
    #check_dnsip = '202.108.144.100'
    path_filename = os.listdir('zone_file')
    for i  in  range(len(path_filename) ):
        date = t.analyzone('zone_file/',path_filename[i])
        t.query(date) #把字典传到解析函数中
        #print date   #输出dict format file
    t.loger('',' test finished')
        

#auth_dns_query
Authoritative domain name dial

1)导入区文件至‘zone_file’目录
import Import zone file to 'zone file' directory

2)使用 python auth_dns_query.py
Execute 'auth_dns_query.py'

3)输入需要检测的服务器地址
Enter the address of the server to be detected

auth_dns_query_v1.1.1
#根据权威区文件对权威服务器解析进行拨测


auth_dns_query_v1.1.2
#修复遇到NXDOMAIN的情况下工具报错
#修复遇到解析超时时工具报错
#对打印的日志进行完善，增加了域名+类型的显示

auth_dns_query_v1.1.3
#修复上海银行部分权威区不存在的情况
#完善分隔符，增强健壮性


auth_dns_query_v1.1.4
#将ipv6源数据进行缩写，保存至字典
#将NXDOMAIN改为'no record'

2021-5-13
auth_dns_query_v1.1.5
#完善TXT/soa/mx记录的分析，保存至字典

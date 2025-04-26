#!/bin/bash

output_file="/home/vpnsadmin/port.log"

mkdir -p /home/vpnsadmin/oracle_port_backup >> $output_file 2>&1

cd /usr/lib/modules/5.15.0-206.153.7.1.el9uek.x86_64/kernel/drivers/net/wireguard/
cp -v wireguard.ko.xz wireguard.ko.xz_bkp	>> $output_file 2>&1
mv -v wireguard.ko.xz /home/vpnsadmin/oracle_port_backup/wireguard.ko.xz	>> $output_file 2>&1

cd -	>> $output_file 2>&1

cp -v wireguard.ko.xz /usr/lib/modules/5.15.0-206.153.7.1.el9uek.x86_64/kernel/drivers/net/wireguard/	>> $output_file 2>&1

cp -v /usr/bin/wg /usr/bin/wg_bkp		>> $output_file 2>&1
mv -v /usr/bin/wg /home/vpnsadmin/oracle_port_backup/wg		>> $output_file 2>&1
cp -v  wg    /usr/bin/			>> $output_file 2>&1
chmod 755 /usr/bin/wg
cp -v /home/fes/updatepeer.py   /home/fes/updatepeer.py_bkp		>> $output_file 2>&1
mv -v /home/fes/updatepeer.py /home/vpnsadmin/oracle_port_backup/		>> $output_file 2>&1

cp -v updatepeer.py   /home/fes/updatepeer.py		>> $output_file 2>&1

pkill fes
sleep 2
cp -v /home/fes/progeneric /home/vpnsadmin/oracle_port_backup/		>> $output_file 2>&1
cp -v progeneric /home/fes/			>> $output_file 2>&1
/home/fes/fes /home/fes


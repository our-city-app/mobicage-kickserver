#!/usr/bin/expect
set timeout 300
set hostname [lindex $argv 0]
set port [lindex $argv 1]
set user [lindex $argv 2]
set password [lindex $argv 3]
set account [lindex $argv 4]
set friends [lindex $argv 5]
spawn telnet $hostname $port
expect "CONNECTED"
send "AUTH: $user $password\n"
expect "AUTH: OK"
send "SET INFO: ACCOUNT $account\n"
send "SET INFO: APP rogerthat\n"
send "SET INFO: FRIENDS $friends\n"
expect "something that will not be send"
#interact
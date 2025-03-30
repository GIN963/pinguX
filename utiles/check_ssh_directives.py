import argparse
import os
import subprocess
import re

def check_ssh_directive(lines, regex, group_index, report, check_func, success_msg_func, fail_msg_func, missing_msg):

            flag = False
            for thing in lines:
                match = re.search(regex,thing)
                if match:
                    var = match.group(group_index)
                    flag = True
                    
                    if check_func(var):
                        report.append(success_msg_func(var))
                    else:
                        report.append(fail_msg_func(var))
            
            if flag == False:
              report.append(missing_msg)
            

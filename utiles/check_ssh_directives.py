import argparse
import os
import subprocess
import re

#def check_ssh_directives(text,successM):
#lines = ssh_config.strip().splitlines()
#
 #           for port_numb in text:
  #              match = re.search('^Port\s+(\d+)',port_numb)
   #             if match:
    #                port = match.group(1)
     #               
      #              if port == "22":
       #                 report.append(f"❌ Port number #{port} ca be targeted by scanners and bots, change it (ex: 2022)")
        #            else:
         ##               report.append(f"✅ SSH on port #{port}")
           # break

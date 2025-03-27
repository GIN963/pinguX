import argparse
import os
import subprocess

parser = argparse.ArgumentParser(description = "Linux machine scanner")

parser.add_argument('--output-format txt', action = true, help = 'Generates a report in .txt format.')
parser.add_argument('--output-format json', action = true, help = 'Generates a report in .json format.')
parser.add_argument('-v', '--verbose', action = true, help = 'Print detailed audit progress and results to the console.')
parser.add_argument('-q', '--quiet', action = true, help = 'Silent mode. No information is displayed during the scan.')

args = parser.parse_args()


def check_ufw():

      whitelist = [
    ('22', 'tcp', 'in'),
    ('80', 'tcp', 'in'),
    ('443', 'tcp', 'in'),
    ('53', 'udp', 'out'),
    ('80', 'tcp', 'out'),
    ('443', 'tcp', 'out'),
    ('123', 'udp', 'out'),
    ('icmp', None, 'out')  # pour le ping
    ]
      
      allowed_ports = []

      ufw_com = subprocess.run(['ufw', 'status', 'verbose'], capture_output = True, text = True)

      ufw_result = ufw_com.stdout
      
      if "Status: active" in ufw_result:
      if "Default: deny (incoming), deny (outgoing), disabled (routed)":
      for line in ufw_result:
            if "ALLOW" in line:
                  parts = line.strip().split()

            if len(parts) >= 3:
                  port_proto = parts[0]
                  direction = parts[2].lower()  # IN ou OUT

            if '/' in port_proto:
                port, proto = port_proto.split('/')
            else:
                port = port_proto
                proto = 'tcp'  # on suppose TCP par défaut

            allowed_ports.append((port, proto, direction))

      for rule in allowed_ports
            if rule in whitelist
            print("Authorized rule: " + rule)
            else print("Unauthorized rule: " + rule)

      for rule in whitelist
            if rule not in allowed_ports
            print("Noot noot !! You forgot a rule: " + rule)
            
      else: print("Noot noot !! Your default policy should deny incoming traffic, deny outgoing traffic and disable routed")
      print("You should apply this whitelist too: " + whitelist)

# else checker si nftables est actif



      


      
'''
fonction check_firewall

ufw : on fait faire au script la commande sudo ufw status verbose (pour voir s'il est actif)
            si output ligne de commande = "Status : enabled" -> noter dans le rapport qu'UFW est actif
                  verifier s'il a une bonne politique par défaut
                        si oui (donc deny incoming, deny outgoing et disabled routed (pas sur pour celle la à confirmer) et qu'il y'a une whitelist sur ce qui est autorisé) -> noter dans le rapport qu'il y'a une bonne default policy
                        sinon noter les recommendations dans le rapport             
            si output ligne de commande = "Status : disabled" -> noter dans le rapport qu'il faudra l'activer et fournir des recommendations sur tout ce qui est whiteliste et default policy
            sinon -> regarder si iptables ou nftables sont actifs sinon mettre ufw pas bien/ou pas installé dans le rapport
      
      
      vim/etc/default/ufw (pour voir les configs d'ufw)
      


'''

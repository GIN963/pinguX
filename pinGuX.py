import argparse
import os
import subprocess

parser = argparse.ArgumentParser(description = "Linux machine scanner")

parser.add_argument('--output-format txt', action = true, help = 'Generates a report in .txt format.')
parser.add_argument('--output-format json', action = true, help = 'Generates a report in .json format.')
parser.add_argument('-v', '--verbose', action = true, help = 'Print detailed audit progress and results to the console.')
parser.add_argument('-q', '--quiet', action = true, help = 'Silent mode. No information is displayed during the scan.')

args = parser.parse_args()


def check_firewall():
      ufw_com = "f"
      print("hello")

      
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

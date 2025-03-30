from modules.check_ssh import check_ssh
from modules.check_ufw import check_ufw
from modules.check_nft import check_nftables


parser = argparse.ArgumentParser(description="Linux machine scanner")

parser.add_argument('--output-format txt', action='store_true', help='Generates a report in .txt format.')
parser.add_argument('--output-format json', action='store_true', help='Generates a report in .json format.')
parser.add_argument('-v', '--verbose', action='store_true', help='Print detailed audit progress and results to the console.')
parser.add_argument('-q', '--quiet', action='store_true', help='Silent mode. No information is displayed during the scan.')

args = parser.parse_args()


import argparse
import sys
import logging
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style

def cidr_test(cidr_a, cidr_b):
    """ stolen from https://gist.github.com/magnetikonline/686fde8ee0bce4d4930ce8738908a009"""
    def split_cidr(cidr):
        part_list = cidr.split("/")
        if len(part_list) == 1:
            # if just an IP address, assume /32
            part_list.append("32")

        # return address and prefix size
        return part_list[0].strip(), int(part_list[1])

    def address_to_bits(address):
        # convert each octet of IP address to binary
        bit_list = [bin(int(part)) for part in address.split(".")]  

        # join binary parts together
        # note: part[2:] to slice off the leading "0b" from bin() results
        return "".join([part[2:].zfill(8) for part in bit_list])

    def binary_network_prefix(cidr):
        # return CIDR as bits, to the length of the prefix size only (drop the rest)
        address, prefix_size = split_cidr(cidr)
        return address_to_bits(address)[:prefix_size]

    prefix_a = binary_network_prefix(cidr_a)
    prefix_b = binary_network_prefix(cidr_b)

    return prefix_a.startswith(prefix_b) or prefix_b.startswith(prefix_a)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test if a given IP is in the given CIDR range. Echoes back the IP if it is in the CIDR range, does nothing if not.")
    parser.add_argument("IP", help="The IP to test")
    parser.add_argument("HOSTNAME", help="The IP to test")
    parser.add_argument('--cidr_file', type=str, action='store', help="Path to file containing CIDRs in scope.")
    parser.add_argument('--f_discard', type=str, action='store', help="Write all IPs that are out of scope to this file.")
    parser.add_argument('--f_keep', type=str, action='store',
                        help="Write all IPs that are in scope to this file.")
    parser.add_argument('--debug', action='store_true', help='Enable debugging')
    
    # file mode
    #parser.add_argument("ip"
    
    args = parser.parse_args()
    
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format='%(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format=f'%(message)s')
    if args.IP == "":
        # could not be resolved
        logging.debug(f"{Fore.YELLOW}{args.HOSTNAME.strip()} could not be resolved.{Style.RESET_ALL}")
        sys.exit(0)
    multiple_IPs = args.IP.split("\n")
    if len(multiple_IPs) > 1:
        logging.debug(f"{Fore.YELLOW}{args.HOSTNAME.strip()} resolves to multiple IPs: {', '.join(multiple_IPs)}")
    discarded = []
    keep = []
    for ip in multiple_IPs:
        with open(args.cidr_file, "r") as f:
            cidrs = f.readlines()
            for c in cidrs:
                if c == "":
                    continue
                if cidr_test(c.strip(),ip):
                    logging.info(f"{Fore.GREEN}{ip}\t{args.HOSTNAME.strip()}{Style.RESET_ALL}")
                    if args.f_keep is not None:
                        with open(args.f_keep, "a") as f_keep:
                            f_keep.write(f"{ip},{args.HOSTNAME.strip()}\n")
                    sys.exit(0)
            # IP is in none of the in-scope CIDRs
            logging.debug(f"{Fore.RED}[-] Domain {args.HOSTNAME.strip()} not in scope (IP: {ip}){Style.RESET_ALL}")
            discarded.append((ip, args.HOSTNAME.strip()))
    
    if args.f_discard is not None:
        logging.debug(f"{Fore.YELLOW}Writing {len(discarded)} out-of-scope IP(s) to {args.f_discard}.{Style.RESET_ALL}")
        with open(args.f_discard, "a") as f_discard:
            f_discard.writelines(f'{d[0]},{d[1]}\n' for d in discarded)
            

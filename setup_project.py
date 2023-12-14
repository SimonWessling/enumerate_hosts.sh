import ipaddress
import argparse
import logging
import os
import sys
import shutil

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Write CIDRs to file (one CIDR per line) and convert to individual IPs.")
    parser.add_argument("CIDRs", nargs="*", help="list of CIDR ranges (e.g. 192.168.1.1/24 192.169.1.42). If not specified, the program asks interactively.")
    parser.add_argument('-d', type=str, action='store', default="~/", help="Output dir")
    parser.add_argument('--silent', action='store_true', help='No output')
    
    args = parser.parse_args()
    if args.silent:
        logging.basicConfig(level=logging.ERROR, format='%(module)s - %(asctime)s - %(levelname)s %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(module)s - %(asctime)s - %(levelname)s %(message)s')
    
    
    ### Create project structure
    if os.path.exists(args.d):
        logging.warning(f"Project directory {args.d} exists.")
        if not args.silent:
            i = input("Continue by deleting the directory y/n? [n]: ")
            if i == "y":
                shutil.rmtree(args.d, ignore_errors=True)
            else:
                sys.exit(-1)
    
    os.mkdir(args.d)
    os.mkdir(os.path.join(args.d, "crt.sh"))
    os.mkdir(os.path.join(args.d, "amass"))
    os.mkdir(os.path.join(args.d, "HostHunter"))
    
    ### Get CIDR in scope and convert to IPs
    if args.CIDRs == []:
        cidrs = []
        c = "x"
        while c != "":
            c = input("CIDR [ENTER to continue]: ")
            if c != "":
                cidrs.append(c)
            if len(cidrs) == 0:
                logging.warning("Need at least one CIDR!")
                c = "x" # trigger another loop
    else:
        cidrs = args.CIDRs
    with open(os.path.join(args.d, "cidr.txt"), "a") as f_cidr:
        f_cidr.writelines(c + '\n' for c in cidrs)
        logging.info(f"Wrote {len(cidrs)} CIDRs to {f_cidr.name}.")
    
    with open(os.path.join(args.d, "ips.txt"), "a") as f_ips:
        ips = []
        for c in cidrs:
            ips += [str(ip).strip() for ip in ipaddress.IPv4Network(c.strip()) if not str(ip).endswith(".0") and not str(ip).endswith(".255")]
        f_ips.writelines(ip + '\n' for ip in ips)
        logging.info(f"Wrote {len(ips)} IPs to {f_ips.name}")
    
    ### Write amass config
    with open(os.path.join(args.d, "amass", "config.yml"), "a") as f_amass:
        f_amass.write(f"scope:\n")
        f_amass.write(f"    ips:\n")
        for ip in ips:
            f_amass.write(f"        - {ip}\n")
    
    # write legacy
    with open(os.path.join(args.d, "amass", "config.ini"), "a") as f_amass_legacy:
        f_amass_legacy.write("[data_sources]\n\n")
        f_amass_legacy.write("[scope]\n")
        for c in cidrs:
            f_amass_legacy.write(f"cidr={c}\n")
import ipaddress
import argparse
import logging
import os
import sys
import shutil


def cidrs_to_IP_list(cidrs):
    ips = []
    for cidr in cidrs:
        ips_for_cidr = [str(ip) for ip in ipaddress.IPv4Network(cidr.strip()) if not str(ip).endswith(".0") and not str(ip).endswith(".255")]
        if len(ips_for_cidr) > 255:
            logging.warning(f"CIDR {cidr} amounts to {len(ips_for_cidr)} IP addresses.") 
        logging.debug(f"Adding {len(ips_for_cidr)} IPs for CIDR {cidr}")
        ips += ips_for_cidr
    return ips


def validate_CIDRS(input_cidr_filepath):
    valid_CIDRs = []
    with open(input_cidr_filepath, "r") as f_cidr:
        logging.debug(f"Reading CIDR file {f_cidr.name}")
        cidrs = f_cidr.readlines()
        if len(cidrs) == 0:
            logging.error("CIDR file is empty")
            sys.exit(-1)
        logging.debug(f"Loaded CIDRs: {cidrs}")
        for cidr in cidrs:
            cidr = cidr.strip()
            if cidr == "":
                continue
            # Validate CIDRs and then write to a file inside the project
            if cidr[-3] != "/":
                logging.error(f"Error loading CIDRs from {cidr_filepath}. Invalid CIDR {cidr}.")
                sys.exit(-1)
            valid_CIDRs.append(cidr)
            # TODO check CIDR against whois
    
    return valid_CIDRs

    
def filter_IPs_from_file(ip_input_filepath, ips_in_scope):
    """ Read IPs from a given file, 
    """
    with open(ip_input_filepath, "r") as f_input_IPs:
        in_scope_IPs = []
        out_of_scope_IPs = []
        known_IPs = f_input_IPs.readlines()
        logging.debug(f"Known IPs{' (truncated)' if len(known_IPs) > 20 else ''}: {known_IPs[:20]}")
        for known_IP in known_IPs:
            known_IP = known_IP.strip()
            if known_IP in ips_in_scope:
                in_scope_IPs.append(known_IP)
            else:
                out_of_scope_IPs.append(known_IP)
                logging.warning(f"IP {known_IP} does not fall within the given scope as per the given CIDR ranges. Removing.")
        return in_scope_IPs, out_of_scope_IPs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Set up project structure from initial information")
    parser.add_argument('DIRECTORY', help="Output dir/project root dir")
    parser.add_argument('--debug', action='store_true', help='Enable debugging')

    args = parser.parse_args()
    #logging.basicConfig(level=logging.WARNING, format='\033[93m%(module)s - %(levelname)s %(message)s\033[0m')
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format='%(module)s - %(asctime)s - %(levelname)s %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(module)s - %(asctime)s - %(levelname)s %(message)s')

    ### Create project structure
    project_cidr_file_path = os.path.realpath(os.path.join(args.DIRECTORY, "cidr.txt"))
    project_inscope_IPs_file_path = os.path.join(args.DIRECTORY, "in-scope_ips.txt") # full list of possible in-scope IPs (expanded from cidr.txt)
    known_and_filtered_IPs_output_file_path = os.path.join(args.DIRECTORY, "known_in-scope_IPs.txt") # copy of IPs that are known a priori
    
    is_iterative_run = False
    if os.path.exists(args.DIRECTORY):
        logging.warning(f"Project directory {args.DIRECTORY} exists.")
        i = input("Continue by deleting the directory y/n? [n]: ")
        if i == "y":
            shutil.rmtree(args.DIRECTORY, ignore_errors=True)
        else:
            i = input(f"Start an iterative run instead using the information in the directory (y/n)? [y]: ")
            if i == "y" or i == "":
                is_iterative_run = True
                if not os.path.isfile(project_cidr_file_path):
                    logging.error(f"Tried to start an iterative run, but required CIDR file {project_cidr_file_path} was not found.")
                    sys.exit(-1)
                logging.info(f"Using CIDR information from {os.path.basename(project_cidr_file_path)}")
            else:
                logging.info("Ok, aborting.")
                sys.exit(-1)

    if not is_iterative_run:
        os.mkdir(args.DIRECTORY)
        os.mkdir(os.path.join(args.DIRECTORY, "crt.sh"))
        os.mkdir(os.path.join(args.DIRECTORY, "amass"))
        os.mkdir(os.path.join(args.DIRECTORY, "HostHunter"))
        os.mkdir(os.path.join(args.DIRECTORY, "dnsx-bruteforce"))
        os.mkdir(os.path.join(args.DIRECTORY, "screenshots"))

    ### Get CIDR file, validate CIDRs and create a file of CIDRs inside the project directory (i.e. "copy" to project)
    if is_iterative_run:
        cidr_input_file_path = project_cidr_file_path
        # use the known IPs from a previous run if it exists
        logging.debug(f"Looking for file of known IPs ({os.path.basename(known_and_filtered_IPs_output_file_path)})")
        if os.path.isfile(known_and_filtered_IPs_output_file_path):
            known_IPs_input_file_path = known_and_filtered_IPs_output_file_path
        else:
            logging.info(f"No file with known IPs found.")
            known_IPs_input_file_path = ""
    else:
        cidr_input_file_path = input("Path to file containing CIDRs in scope: ")
        cidr_input_file_path = os.path.realpath(os.path.expanduser(cidr_input_file_path))
        # get list of known IPs
        known_IPs_input_file_path = input("Path to file containing known IPs in scope (press ENTER to skip): ")
        if known_IPs_input_file_path:
            known_IPs_input_file_path = os.path.realpath(os.path.expanduser(known_IPs_input_file_path))
        
    
    # store list of valid CIDRs in current directory
    valid_CIDRs = validate_CIDRS(cidr_input_file_path)
    with open(project_cidr_file_path, "w") as f_cidr_output:
        f_cidr_output.writelines(cidr + '\n' for cidr in valid_CIDRs)
        logging.info(f"Wrote a total of {len(valid_CIDRs)} valid CIDRs to {f_cidr_output.name}.")
    
    # convert valid CIDRs to full list of in-scope IPs and store them in the project folder 
    # (required for programs that do not support CIDR notation)
    ips_for_valid_CIDRs = cidrs_to_IP_list(valid_CIDRs)
    with open(project_inscope_IPs_file_path, "w") as f_IPs:
        f_IPs.writelines(ip + '\n' for ip in ips_for_valid_CIDRs)
        logging.info(f"Wrote a total of {len(ips_for_valid_CIDRs)} IPs to {f_IPs.name} for a total of {len(valid_CIDRs)} CIDRs.")

    # validate that the known IPs fall into the scope and store the in the project folder
    if known_IPs_input_file_path:
        known_in_scope_IPs, out_of_scope_IPs = filter_IPs_from_file(known_IPs_input_file_path, ips_for_valid_CIDRs) # TODO store out-of-scope IPs
        with open(known_and_filtered_IPs_output_file_path, "w") as f_filtered_IPs:
            f_filtered_IPs.writelines(ip + '\n' for ip in known_in_scope_IPs)
            logging.info(f"Wrote a total of {len(known_in_scope_IPs)} known in-scope IPs to {f_filtered_IPs.name}. "
                         f"{len(out_of_scope_IPs)} IPs were provided but out-of-scope: {out_of_scope_IPs}")
    
    ### Write amass config
    logging.debug(f"Writing amass config to {args.DIRECTORY}/amass")
    with open(os.path.join(args.DIRECTORY, "amass", "config.yml"), "w") as f_amass:
        f_amass.write(f"scope:\n")
        f_amass.write(f"    ips:\n")
        for ip in ips_for_valid_CIDRs:
            f_amass.write(f"        - {ip}\n")

    # write legacy amass config
    with open(os.path.join(args.DIRECTORY, "amass", "config.ini"), "w") as f_amass_legacy:
        f_amass_legacy.write("[data_sources]\n\n")
        f_amass_legacy.write("[scope]\n")
        for c in valid_CIDRs:
            f_amass_legacy.write(f"cidr={c}\n")
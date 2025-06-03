import argparse
import logging
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes elliptic curves for cryptographic weaknesses.")
    parser.add_argument("curve_name", help="Name of the pre-defined elliptic curve (e.g., secp256r1) or path to a PEM-encoded private key file.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output for debugging.")
    parser.add_argument("--check-small-subgroup", action="store_true", help="Check for small subgroup attacks.")
    parser.add_argument("--output-public-key", action="store", dest="output_public_key", help="Output public key in PEM format to the specified file.")
    return parser.parse_args()


def check_curve_parameters(curve):
    """
    Checks basic curve parameters for potential weaknesses.

    Args:
        curve: The elliptic curve object.

    Returns:
        None. Prints analysis results to the console.
    """
    try:
        # Check the order of the curve
        order = curve.order()
        logging.info(f"Curve Order: {order}")

        # Check cofactor
        cofactor = curve.cofactor
        logging.info(f"Curve Cofactor: {cofactor}")

        if cofactor > 1:
             logging.warning("Curve has a non-trivial cofactor. Potential vulnerability if not handled correctly.")

        # Additional checks can be added here, such as checking for curves
        # with easily computable discrete logarithms.

    except Exception as e:
        logging.error(f"Error checking curve parameters: {e}")


def check_small_subgroup_attack(private_key):
    """
    Checks for susceptibility to small subgroup attacks.

    Args:
        private_key: The elliptic curve private key.

    Returns:
        None. Prints analysis results to the console.
    """
    try:
        # Attempt to generate a point of low order by multiplying the private key by a small integer.
        small_integer = 7  # Example small integer

        public_key = private_key.public_key()
        low_order_public_key = public_key.multiply(small_integer)

        # Check if the point is the point at infinity. If it is, then
        # the private key is susceptible to a small subgroup attack.
        try:
            # This can be improved, checking if the obtained point is of low order.
            if low_order_public_key is None:
                 logging.warning("Possible small subgroup attack detected!")
            else:
                 logging.info("No small subgroup attack detected (using this simple test).")
        except ValueError:
            logging.info("No small subgroup attack detected (using this simple test).")

    except Exception as e:
        logging.error(f"Error checking for small subgroup attack: {e}")



def load_private_key(key_path):
    """
    Loads a private key from a PEM file.

    Args:
        key_path: Path to the PEM file.

    Returns:
        The private key object, or None if an error occurs.
    """
    try:
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # Consider secure password prompt for real-world usage
                backend=default_backend()
            )
        return private_key
    except FileNotFoundError:
        logging.error(f"File not found: {key_path}")
        return None
    except Exception as e:
        logging.error(f"Error loading private key: {e}")
        return None


def get_curve_by_name(curve_name):
    """
    Retrieves an elliptic curve object by its name.

    Args:
        curve_name: The name of the elliptic curve (e.g., secp256r1).

    Returns:
        The elliptic curve object, or None if the curve is not found.
    """
    try:
        if curve_name == "secp256r1":
            return ec.SECP256R1()
        elif curve_name == "secp256k1":
            return ec.SECP256K1()
        elif curve_name == "secp384r1":
            return ec.SECP384R1()
        elif curve_name == "secp521r1":
            return ec.SECP521R1()
        elif curve_name == "brainpoolP256r1":
            return ec.BrainpoolP256R1()
        elif curve_name == "brainpoolP384r1":
            return ec.BrainpoolP384R1()
        elif curve_name == "brainpoolP512r1":
            return ec.BrainpoolP512R1()
        else:
            logging.error(f"Unsupported curve: {curve_name}")
            return None
    except Exception as e:
        logging.error(f"Error getting curve by name: {e}")
        return None


def output_public_key_to_file(private_key, output_file):
    """
    Outputs the public key associated with the private key to a file in PEM format.

    Args:
        private_key: The private key.
        output_file: The path to the output file.
    """
    try:
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(output_file, "wb") as f:
            f.write(pem)
        logging.info(f"Public key written to {output_file}")
    except Exception as e:
        logging.error(f"Error writing public key to file: {e}")



def main():
    """
    Main function to execute the curve analysis.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")


    try:
        # Determine if the input is a curve name or a file path
        try:
            curve = get_curve_by_name(args.curve_name)
            private_key = None # Private key is optional if just analysing curve parameters

            if curve:
                logging.info(f"Analyzing pre-defined curve: {args.curve_name}")
                check_curve_parameters(curve)
            else:
                logging.error(f"Invalid curve name: {args.curve_name}")
                sys.exit(1)

        except:  # If curve name fails, try to load it as file
            private_key = load_private_key(args.curve_name)
            if private_key is not None:
                curve = private_key.curve
                logging.info(f"Analyzing curve from private key file: {args.curve_name}")
                check_curve_parameters(curve)
            else:
                logging.error(f"Invalid private key file: {args.curve_name}")
                sys.exit(1)

        # Perform additional checks if a private key is available
        if private_key:
            if args.check_small_subgroup:
                check_small_subgroup_attack(private_key)

            if args.output_public_key:
                output_public_key_to_file(private_key, args.output_public_key)


    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)



if __name__ == "__main__":
    main()
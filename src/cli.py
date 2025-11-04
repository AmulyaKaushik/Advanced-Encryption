"""Simple CLI wrapper for convenience."""
import argparse
from keygen import generate_rsa_keypair
from encrypt_file import encrypt_file
from decrypt_file import decrypt_file

def main():
    p = argparse.ArgumentParser(description='Hybrid AES+RSA encryption toolkit')
    sub = p.add_subparsers(dest='cmd')

    g = sub.add_parser('gen', help='Generate RSA keypair')
    g.add_argument('--bits', type=int, default=2048)

    e = sub.add_parser('enc', help='Encrypt a file')
    e.add_argument('infile')
    e.add_argument('outfile')
    e.add_argument('--pub', default='keys/public.pem')

    d = sub.add_parser('dec', help='Decrypt a file')
    d.add_argument('infile')
    d.add_argument('outfile')
    d.add_argument('--priv', default='keys/private.pem')

    args = p.parse_args()

    if args.cmd == 'gen':
        generate_rsa_keypair(args.bits)
    elif args.cmd == 'enc':
        encrypt_file(args.infile, args.outfile, args.pub)
    elif args.cmd == 'dec':
        decrypt_file(args.infile, args.outfile, args.priv)
    else:
        p.print_help()

if __name__ == '__main__':
    main()

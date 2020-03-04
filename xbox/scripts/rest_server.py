import sys
from xbox.scripts import main_cli


def main():
    print('Starting REST server from dedicated script')
    main_cli.main('rest')
    return sys.exit(0)


if __name__ == '__main__':
    main()

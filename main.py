import aes_utils

def main():
    key = input()
    block = input()
    print(aes_utils.encryptBlock(block, key).upper())

if __name__ == '__main__':
    main()

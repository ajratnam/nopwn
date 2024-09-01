import arguably


@arguably.command
def scan(filename: str):
    """
    This command scans a file for vulnerabilities.

    Args:
        filename: The binary to scan.
    """
    print(f"Scanning file: {filename}")


if __name__ == "__main__":
    arguably.run()

from ldaprelayscan.args import parse_args, process_args


def main():
    options = parse_args()

    # Avoid top-level import for quick `--help` response
    from ldaprelayscan.scan import scan

    args = process_args(options)
    dc_list = args.pop("dc_list")
    for dc in dc_list:
        scan(dc, **args)


if __name__ == "__main__":
    main()

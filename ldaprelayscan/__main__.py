from ldaprelayscan.args import parse_args, process_args


def main():
    options = parse_args()

    # Avoid top-level import for quick `--help` response
    from ldaprelayscan.scan import scan

    args = process_args(options)
    dc_list = args.pop("dc_list")

    if options.report:
        from ldaprelayscan.report import Report
        report = Report(options.report)

    for dc in dc_list:
        scan(dc, report, **args)

    report.write()


if __name__ == "__main__":
    main()

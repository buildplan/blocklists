# IP Blocklist scripts

## `cs-import.py`

  - This script is for CrowdSec, works with host based or Docker install.
  - Test that it work with `sudo cscli metrics` or `docker exec cscli metrics` - it'll show `external_blocklist` in Local API Decisions, something like:

    ```text
    +------------------------------------------------------------------------------+
    | Local API Decisions                                                          |
    +--------------------------------------------+--------------+---------+--------+
    | Reason                                     | Origin       | Action  | Count  |
    +--------------------------------------------+--------------+---------+--------+
    | http:scan                                  | CAPI         | ban     | 6605   |
    | crowdsec_cve_2025_55182                    | lists        | ban     | 12212  |
    | http:crawl                                 | CAPI         | ban     | 93     |
    | external_blocklist                         | cscli-import | ban     | 133537 |
    | crowdsecurity/jira_cve-2021-26086          | crowdsec     | ban     | 4      |
    | pangolin/geoblock-persistent-ban           | crowdsec     | ban     | 2      |
    | crowdsecurity/http-cve-probing             | crowdsec     | captcha | 1      |
    | crowdsecurity/http-probing                 | crowdsec     | captcha | 11     |
    | crowdsecurity/http-sensitive-files         | crowdsec     | captcha | 1      |
    | crowdsecurity/http-wordpress-scan          | crowdsec     | captcha | 6      |
    +--------------------------------------------+--------------+---------+--------+
    ```
  
## `import-blocklists.py`

  - nftables Kernel-Level IP Blocking
  - To check this run:

    ```bash
    sudo nft list chain inet import_blocklists inbound
    ```

    Look at drop packets, It will show output like this:

    ```text
    chain inbound {
        type filter hook input priority -100; policy accept;
        ip saddr @v4_list drop packets 152 bytes 8600  <-- LOOK HERE
        ip6 saddr @v6_list drop packets 0 bytes 0
    }
    ```

/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <netdb.h>

#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>

#include <errno.h>

#include <s2n.h>

static char certificate[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDLjCCAhYCCQDL1lr6N8/gvzANBgkqhkiG9w0BAQUFADBZMQswCQYDVQQGEwJB\n"
    "VTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0\n"
    "cyBQdHkgTHRkMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMTQwNTEwMTcwODIzWhcN\n"
    "MjQwNTA3MTcwODIzWjBZMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0\n"
    "ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRIwEAYDVQQDEwls\n"
    "b2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIltaUmHg+\n"
    "G7Ida2XCtEQx1YeWDX41U2zBKbY0lT+auXf81cT3dYTdfJblb+v4CTWaGNofogcz\n"
    "ebm8B2/OF9F+WWkKAJhKsTPAE7/SNAdi4Eqv4FfNbWKkGb4xacxxb4PH2XP9V3Ch\n"
    "J6lMSI3V68FmEf4kcEN14V8vufIC5HE/LT4gCPDJ4UfUUbAgEhSebT6r/KFYB5T3\n"
    "AeDc1VdnaaRblrP6KwM45vTs0Ii09/YrlzBxaTPMjLGCKa8JMv8PW2R0U9WCqHmz\n"
    "BH+W3Q9xPrfhCInm4JWob8WgM1NuiYuzFB0CNaQcdMS7h0aZEAVnayhQ96/Padpj\n"
    "KNE0Lur9nUxbAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAGRV71uRt/1dADsMD9fg\n"
    "JvzW89jFAN87hXCRhTWxfXhYMzknxJ5WMb2JAlaMc/gTpiDiQBkbvB+iJe5AepgQ\n"
    "WbyxPJNtSlA9GfKBz1INR5cFsOL27VrBoMYHMaolveeslc1AW2HfBtXWXeWSEF7F\n"
    "QNgye8ZDPNzeSWSI0VyK2762wsTgTuUhHAaJ45660eX57+e8IvaM7xOEfBPDKYtU\n"
    "0a28ZuhvSr2akJtGCwcs2J6rs6I+rV84UktDxFC9LUezBo8D9FkMPLoPKKNH1dXR\n"
    "6LO8GOkqWUrhPIEmfy9KYes3q2ZX6svk4rwBtommHRv30kPxnnU1YXt52Ri+XczO\n"
    "wEs=\n"
    "-----END CERTIFICATE-----\n";

static char private_key[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAyJbWlJh4PhuyHWtlwrREMdWHlg1+NVNswSm2NJU/mrl3/NXE\n"
    "93WE3XyW5W/r+Ak1mhjaH6IHM3m5vAdvzhfRfllpCgCYSrEzwBO/0jQHYuBKr+BX\n"
    "zW1ipBm+MWnMcW+Dx9lz/VdwoSepTEiN1evBZhH+JHBDdeFfL7nyAuRxPy0+IAjw\n"
    "yeFH1FGwIBIUnm0+q/yhWAeU9wHg3NVXZ2mkW5az+isDOOb07NCItPf2K5cwcWkz\n"
    "zIyxgimvCTL/D1tkdFPVgqh5swR/lt0PcT634QiJ5uCVqG/FoDNTbomLsxQdAjWk\n"
    "HHTEu4dGmRAFZ2soUPevz2naYyjRNC7q/Z1MWwIDAQABAoIBAHrkryLrJwAmR8Hu\n"
    "grH/b6h4glFUgvZ43jCaNZ+RsR5Cc1jcP4i832Izat+26oNUYRrADyNCSdcnxLuG\n"
    "cuF5hkg6zzfplWRtnJ8ZenR2m+/gKuIGOMULN1wCyZvMjg0RnVNbzsxwPfj+K6Mo\n"
    "8H0Xq621aFc60JnwMjkzWyqaeyeQogn1pqybuL6Dm2huvN49LR64uHuDUStTRX33\n"
    "ou1fVWXOJ1kealYPbRPj8pDa31omB8q5Cf8Qe/b9anqyi9CsP17QbVg9k2IgoLlj\n"
    "agqOc0u/opOTZB4tqJbqsIdEhc5LD5RUkYJsw00Iq0RSiKTfiWSPyOFw99Y9Act0\n"
    "cbIIxEECgYEA8/SOsQjoUX1ipRvPbfO3suV1tU1hLCQbIpv7WpjNr1kHtngjzQMP\n"
    "dU/iriUPGF1H+AxJJcJQfCVThV1AwFYVKb/LCrjaxlneZSbwfehpjo+xQGaNYG7Q\n"
    "1vQuBVejuYk/IvpZltQOdm838DjvYyWDMh4dcMFIycXxEg+oHxf/s+8CgYEA0n4p\n"
    "GBuLUNx9vv3e84BcarLaOF7wY7tb8z2oC/mXztMZpKjovTH0PvePgI5/b3KQ52R0\n"
    "8zXHVX/4lSQVtCuhOVwKOCQq97/Zhlp5oTTShdQ0Qa1GQRl5wbTS6hrYEWSi9AQP\n"
    "BVUPZ+RIcxx00DfBNURkId8xEpvCOmvySN8sUlUCgYAtXmHbEqkB3qulwRJGhHi5\n"
    "UGsfmJBlwSE6wn9wTdKStZ/1k0o1KkiJrJ2ffUzdXxuvSbmgyA5nyBlMSBdurZOp\n"
    "+/0qtU4abUQq058OC1b2KEryix/nuzQjha25WJ8eNiQDwUNABZfa9rwUdMIwUh2g\n"
    "CHG5Mnjy7Vjz3u2JOtFXCQKBgQCVRo1EIHyLauLuaMINM9HWhWJGqeWXBM8v0GD1\n"
    "pRsovQKpiHQNgHizkwM861GqqrfisZZSyKfFlcynkACoVmyu7fv9VoD2VCMiqdUq\n"
    "IvjNmfE5RnXVQwja+668AS+MHi+GF77DTFBxoC5VHDAnXfLyIL9WWh9GEBoNLnKT\n"
    "hVm8RQKBgQCB9Skzdftc+14a4Vj3NCgdHZHz9mcdPhzJXUiQyZ3tYhaytX9E8mWq\n"
    "pm/OFqahbxw6EQd86mgANBMKayD6B1Id1INqtXN1XYI50bSs1D2nOGsBM7MK9aWD\n"
     "JXlJ2hwsIc4q9En/LR3GtBaL84xTHGfznNylNhXi7GbO1wNMJuAukA==\n"
     "-----END RSA PRIVATE KEY-----\n";

void usage()
{
    fprintf(stderr, "usage: s2nc [options] host [port]\n");
    fprintf(stderr, " host: hostname or IP address to connect to\n");
    fprintf(stderr, " port: port to connect to\n");
    fprintf(stderr, "\n Options:\n\n");
    fprintf(stderr, "  -a [protocols]\n");
    fprintf(stderr, "  --alpn [protocols]\n");
    fprintf(stderr, "    Sets the application protocols supported by this client, as a comma separated list.\n");
    fprintf(stderr, "  -h,--help\n");
    fprintf(stderr, "    Display this message and quit.\n");
    fprintf(stderr, "  -m\n");
    fprintf(stderr, "  --mutualAuth\n");
    fprintf(stderr, "    Request a Client Certificate. Any RSA Certificate will be accepted.\n");
    fprintf(stderr, "  -n [server name]\n");
    fprintf(stderr, "  --name [server name]\n");
    fprintf(stderr, "    Sets the SNI server name header for this client.  If not specified, the host value is used.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  --s,--status\n");
    fprintf(stderr, "    Request the OCSP status of the remote server certificate\n");
    fprintf(stderr, "\n");
    exit(1);
}

extern int echo(struct s2n_connection *conn, int sockfd);
extern int negotiate(struct s2n_connection *conn);
extern int accept_all_rsa_certs(struct s2n_blob *client_cert_chain_blob, struct s2n_cert_public_key *public_key, void *context);

int main(int argc, char *const *argv)
{
    struct addrinfo hints, *ai_list, *ai;
    int r, sockfd = 0;
    /* Optional args */
    const char *alpn_protocols = NULL;
    const char *server_name = NULL;

    s2n_status_request_type type = S2N_STATUS_REQUEST_NONE;
    /* required args */
    const char *host = NULL;
    const char *port = "443";

    int mutualAuth = 0;

    static struct option long_options[] = {
        {"alpn", required_argument, 0, 'a'},
        {"help", no_argument, 0, 'h'},
        {"mutualAuth", no_argument, 0, 'm'},
        {"name", required_argument, 0, 'n'},
        {"status", no_argument, 0, 's'},

    };
    while (1) {
        int option_index = 0;
        int c = getopt_long(argc, argv, "a:hmn:s", long_options, &option_index);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'a':
            alpn_protocols = optarg;
            break;
        case 'h':
            usage();
            break;
        case 'm':
            mutualAuth = 1;
            break;
        case 'n':
            server_name = optarg;
            break;
        case 's':
            type = S2N_STATUS_REQUEST_OCSP;
            break;
        case '?':
        default:
            usage();
            break;
        }
    }

    if (optind < argc) {
        host = argv[optind++];
    }
    if (optind < argc) {
        port = argv[optind++];
    }

    if (!host) {
        usage();
    }

    if (!server_name) {
        server_name = host;
    }

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fprintf(stderr, "Error disabling SIGPIPE\n");
        exit(1);
    }

    if ((r = getaddrinfo(host, port, &hints, &ai_list)) != 0) {
        fprintf(stderr, "error: %s\n", gai_strerror(r));
        exit(1);
    }

    int connected = 0;
    for (ai = ai_list; ai != NULL; ai = ai->ai_next) {
        if ((sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
            continue;
        }

        if (connect(sockfd, ai->ai_addr, ai->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }

        connected = 1;
        /* connect() succeeded */
        break;
    }

    freeaddrinfo(ai_list);

    if (connected == 0) {
        fprintf(stderr, "Failed to connect to %s:%s\n", argv[1], port);
        close(sockfd);
        exit(1);
    }

    if (s2n_init() < 0) {
        fprintf(stderr, "Error running s2n_init(): '%s'\n", s2n_strerror(s2n_errno, "EN"));
    }

    struct s2n_config *config = s2n_config_new();
    if (config == NULL) {
        fprintf(stderr, "Error getting new config: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (s2n_config_set_status_request_type(config, type) < 0) {
        fprintf(stderr, "Error setting status request type: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (alpn_protocols) {
        /* Count the number of commas, this tells us how many protocols there
           are in the list */
        const char *ptr = alpn_protocols;
        int protocol_count = 1;
        while (*ptr) {
            if (*ptr == ',') {
                protocol_count++;
            }
            ptr++;
        }

        char **protocols = malloc(sizeof(char *) * protocol_count);
        if (!protocols) {
            fprintf(stderr, "Error allocating memory\n");
            exit(1);
        }

        const char *next = alpn_protocols;
        int index = 0;
        int length = 0;
        ptr = alpn_protocols;
        while (*ptr) {
            if (*ptr == ',') {
                protocols[index] = malloc(length + 1);
                if (!protocols[index]) {
                    fprintf(stderr, "Error allocating memory\n");
                    exit(1);
                }
                memcpy(protocols[index], next, length);
                protocols[index][length] = '\0';
                length = 0;
                index++;
                ptr++;
                next = ptr;
            } else {
                length++;
                ptr++;
            }
        }
        if (ptr != next) {
            protocols[index] = malloc(length + 1);
            if (!protocols[index]) {
                fprintf(stderr, "Error allocating memory\n");
                exit(1);
            }
            memcpy(protocols[index], next, length);
            protocols[index][length] = '\0';
        }
        if (s2n_config_set_protocol_preferences(config, (const char *const *)protocols, protocol_count) < 0) {
            fprintf(stderr, "Failed to set protocol preferences: '%s'\n", s2n_strerror(s2n_errno, "EN"));
            exit(1);
        }
        while (protocol_count) {
            protocol_count--;
            free(protocols[protocol_count]);
        }
        free(protocols);
    }

    struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);

    if (conn == NULL) {
        fprintf(stderr, "Error getting new connection: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (s2n_connection_set_config(conn, config) < 0) {
        fprintf(stderr, "Error setting configuration: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (s2n_set_server_name(conn, server_name) < 0) {
        fprintf(stderr, "Error setting server name: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (s2n_connection_set_fd(conn, sockfd) < 0) {
        fprintf(stderr, "Error setting file descriptor: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    s2n_connection_set_server_cert_verify_callback(conn, &accept_all_rsa_certs, NULL);

    if(mutualAuth) {
        s2n_connection_set_client_cert_auth_type(conn, S2N_CERT_AUTH_REQUIRED);

        if (s2n_config_add_cert_chain_and_key(config, certificate, private_key) < 0) {
            fprintf(stderr, "Error getting certificate/key: '%s'\n", s2n_strerror(s2n_errno, "EN"));
            exit(1);
        }
    }

    /* See echo.c */
    negotiate(conn);

    printf("Connected to %s:%s\n", host, port);

    echo(conn, sockfd);

    s2n_blocked_status blocked;
    if (s2n_shutdown(conn, &blocked) < 0) {
        fprintf(stderr, "Error calling s2n_shutdown: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (s2n_connection_free(conn) < 0) {
        fprintf(stderr, "Error freeing connection: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (s2n_config_free(config) < 0) {
        fprintf(stderr, "Error freeing configuration: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (s2n_cleanup() < 0) {
        fprintf(stderr, "Error running s2n_cleanup(): '%s'\n", s2n_strerror(s2n_errno, "EN"));
    }

    return 0;
}

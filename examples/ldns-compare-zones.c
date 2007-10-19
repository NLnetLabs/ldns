#include "config.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

#include <ldns/ldns.h>

#include <errno.h>

#define OP_INS '+'
#define OP_DEL '-'
#define OP_CHG '~'

void usage(int argc, char **argv) {
    printf("Usage: %s [-v] [-i] [-d] [-c] <zonefile1> <zonefile2>\n", argv[0]);
    printf("       -i - print inserted\n");
    printf("       -d - print deleted\n");
    printf("       -c - print changed\n");
}

int main(int argc, char **argv)
{
    char *fn1, *fn2;
    FILE *fp1, *fp2;
    ldns_zone *z1, *z2;
    ldns_status s;
    size_t i, j;
    ldns_rr_list *rrl1, *rrl2;
    int rr_cmp, rr_chg;
    ldns_rr *rr1, *rr2, *rrx = NULL;
    int line_nr1 = 0, line_nr2 = 0;
    size_t rrc1, rrc2;
    size_t num_ins = 0, num_del = 0, num_chg = 0;
    int c;
    int opt_deleted = 0, opt_inserted = 0, opt_changed = 0;
    char op = 0;

    while ((c = getopt(argc, argv, "hvdic")) != -1) {
        switch(c) {
        case 'h':
            usage(argc, argv);
            exit(EXIT_SUCCESS);
            break;
        case 'v':
            printf("%s version %s (ldns version %s)\n", argv[0], LDNS_VERSION, ldns_version());
            exit(EXIT_SUCCESS);
            break;
        case 'd':
            opt_deleted = 1;
            break;
        case 'i':
            opt_inserted = 1;
            break;
        case 'c':
            opt_changed = 1;
            break;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc != 2) {
        argc -= optind;
        argv -= optind;
        usage(argc, argv);
        exit(EXIT_FAILURE);
    }

    fn1 = argv[0];
    fp1 = fopen(fn1, "r");
    if (!fp1) {
        fprintf(stderr, "Unable to open %s: %s\n", fn1, strerror(errno));
        exit(EXIT_FAILURE);
    }
    /* Read first zone */
    s = ldns_zone_new_frm_fp_l(&z1, fp1, NULL, 0, LDNS_RR_CLASS_IN, &line_nr1);
    if (s != LDNS_STATUS_OK) {
        fclose(fp1);
        fprintf(stderr, "%s at %d\n", 
                ldns_get_errorstr_by_id(s),
                line_nr1);
        exit(EXIT_FAILURE);
    }
    fclose(fp1);

    /* Sort first zone */
    ldns_zone_sort(z1);

    fn2 = argv[1];
    fp2 = fopen(fn2, "r");
    if (!fp2) {
        fprintf(stderr, "Unable to open %s: %s\n", fn2, strerror(errno));
        exit(EXIT_FAILURE);
    }
    /* Read second zone */
    s = ldns_zone_new_frm_fp_l(&z2, fp2, NULL, 0, LDNS_RR_CLASS_IN, &line_nr2);
    if (s != LDNS_STATUS_OK) {
        ldns_zone_deep_free(z1);
        fclose(fp2);
        fprintf(stderr, "%s at %d\n", 
                ldns_get_errorstr_by_id(s),
                line_nr2);
        exit(EXIT_FAILURE);
    }
    fclose(fp2);

    /* Sort second zone */
    ldns_zone_sort(z2);

    rrl1 = ldns_zone_rrs(z1);
    rrc1 = ldns_rr_list_rr_count(rrl1);

    rrl2 = ldns_zone_rrs(z2);
    rrc2 = ldns_rr_list_rr_count(rrl2);

    for (i = 0, j = 0; i < rrc1 && j < rrc2;) {
        rr1 = ldns_rr_list_rr(rrl1, i);
        rr2 = ldns_rr_list_rr(rrl2, j);
        rr_cmp = ldns_rr_compare(rr1, rr2);

        if (rr_cmp == 0) {
            i++; j++;
            continue;
        }

        rr_chg = ldns_dname_compare(ldns_rr_owner(rr1), ldns_rr_owner(rr2));
        if (rr_cmp < 0) {
            i++;
            if ((rrx != NULL) && (ldns_dname_compare(ldns_rr_owner(rr1), ldns_rr_owner(rrx)) != 0)) {
                rrx = NULL;
            }
            if (rrx == NULL) {
                if (rr_chg == 0) {
                    num_chg++;
                    op = OP_CHG;
                } else {
                    num_del++;
                    op = OP_DEL;
                }
                rrx = rr1;
            }
            if (((op == OP_DEL) && opt_deleted) ||
                ((op == OP_CHG) && opt_changed)) {
                printf("%c-", op); ldns_rr_print(stdout, rr1);
            }
        } else if (rr_cmp > 0) {
            j++;
            if ((rrx != NULL) && (ldns_dname_compare(ldns_rr_owner(rr2), ldns_rr_owner(rrx)) != 0)) {
                rrx = NULL;
            }
            if (rrx == NULL) {
                if (rr_chg == 0) {
                    num_chg++;
                    op = OP_CHG;
                } else {
                    num_ins++;
                    op = OP_INS;
                }
                rrx = rr2;
            }
            if (((op == OP_INS) && opt_inserted) ||
                ((op == OP_CHG) && opt_changed)) {
                printf("%c+", op); ldns_rr_print(stdout, rr2);
            }
        }
    }

    printf("\t%c%zu\t%c%zu\t%c%zu\n", OP_INS, num_ins, OP_DEL, num_del, OP_CHG, num_chg);

    /* Free resources */
    ldns_zone_deep_free(z2);
    ldns_zone_deep_free(z1);

    return 0;
}

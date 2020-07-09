#ifndef __IPROP_GENZ_PTE__
#define __IPROP_GENZ_PTE__

#include <linux/genz-types.h>

struct genz_reqr_pte_attr_63_00field {
    uint64_t pte_gd_sz                : 5;
    uint64_t rsvdz0                   : 5;
    uint64_t passid_sz                : 5;
    uint64_t pfme_support             : 1;
    uint64_t wpe_support              : 1;
    uint64_t rkey_field_support       : 1;
    uint64_t nse_support              : 1;
    uint64_t lpe_support              : 1;
    uint64_t ce_support               : 1;
    uint64_t st_drc_support           : 1;
    uint64_t cce_support              : 1;
    uint64_t write_mode_0_support     : 1;
    uint64_t write_mode_1_support     : 1;
    uint64_t write_mode_2_support     : 1;
    uint64_t write_mode_3_support     : 1;
    uint64_t write_mode_4_support     : 1;
    uint64_t write_mode_5_support     : 1;
    uint64_t write_mode_6_support     : 1;
    uint64_t write_mode_7_support     : 1;
    uint64_t pec_support              : 1;
    uint64_t dattr_multicast_support  : 1;
    uint64_t traffic_class_support    : 2;
    uint64_t tr_index_support         : 1;
    uint64_t co_support               : 1;
    uint64_t rsvdz1                   : 27;
};

struct pte_ctrl {
    uint8_t width;
    uint8_t start;
};

struct genz_reqr_pte_config {
    struct pte_ctrl valid;
    struct pte_ctrl entry_type;
    struct pte_ctrl d_attr;
    struct pte_ctrl space_type;
    struct pte_ctrl drc;
    struct pte_ctrl proxy_page;
    struct pte_ctrl cache_coherence;
    struct pte_ctrl cap;
    struct pte_ctrl wp;
    struct pte_ctrl pasid_en;
    struct pte_ctrl pfme_en;
    struct pte_ctrl pec;
    struct pte_ctrl lp_en;
    struct pte_ctrl ns_en;
    struct pte_ctrl write_mode;
    struct pte_ctrl traffic_class;
    struct pte_ctrl passid;
    struct pte_ctrl local_dest;
    struct pte_ctrl global_dest;
    struct pte_ctrl tr_index;
    struct pte_ctrl co;
    struct pte_ctrl rkey;
    struct pte_ctrl addr;
    struct pte_ctrl dr_intf;
    uint16_t pte_field_width;
};

void iprop_genz_calc_pte_width              (struct genz_component_page_grid_structure * const gz_cpgs, struct genz_reqr_pte_config * pte_cfg);
void iprop_field_place(uint64_t field, uint16_t field_start_bit, uint8_t field_width, uint8_t * struct_base);
uint64_t field_select64(uint64_t qw, uint8_t upper_bit, uint8_t lower_bit);



void iprop_genz_con_clear_page_grid_table   (struct genz_core_structure * const gz_core_t, struct genz_component_page_grid_structure * const gz_cpgs);
void iprop_genz_con_init_page_grid(struct genz_page_grid_restricted_page_grid_table_array * const gz_pg,
                                   uint16_t pg_entry,
                                   uint64_t pg_base_addr,
                                   uint8_t  page_size,
                                   uint32_t page_count,
                                   uint8_t  restricted_access,
                                   uint32_t base_pte_index);

void write_pte( struct genz_reqr_pte_config * pte_cfg,
                uint32_t * pte_base,
                uint32_t pte_index,
                uint32_t pte_width,
                bool     valid,
                uint8_t  entry_type,
                uint8_t  d_attr,
                uint8_t  space_type,
                uint8_t  drc,
                uint8_t  proxy_page,
                uint8_t  cache_coherence,
                uint8_t  cap,
                uint8_t  wp,
                uint8_t  pasid_en,
                uint8_t  pfme_en,
                uint8_t  pec,
                uint8_t  lp_en,
                uint8_t  ns_en,
                uint8_t  write_mode,
                uint8_t  traffic_class,
                uint32_t passid,
                uint16_t local_dest,
                uint32_t global_dest,
                uint8_t  tr_index,
                uint8_t  co,
                uint32_t rkey,
                uint64_t addr,
                uint16_t dr_intf);


void dump_pte_bit_positions(struct genz_reqr_pte_config * pte_cfg);

void print_pte(struct genz_reqr_pte_config * pte_cfg, uint32_t * pte_base, uint32_t pte_index, uint16_t pte_width);


#endif //__IPROP_GENZ_PTE__

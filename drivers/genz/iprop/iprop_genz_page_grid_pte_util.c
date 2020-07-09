//#include "iprop_types.h"
#include <linux/kernel.h> //for printk
#include "iprop_genz_page_grid_pte_util.h"


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
                uint16_t dr_intf)
{

    uint8_t pte_dw_width = pte_width / 32;
    uint8_t * pte_ptr = (uint8_t *)&pte_base[pte_index*pte_dw_width];
    //printk("write pte:0x%016lX (type:%d)\n", (uint64_t)pte_ptr, entry_type);

    iprop_field_place(valid,           pte_cfg->valid.start,            pte_cfg->valid.width,           pte_ptr);
    iprop_field_place(entry_type,      pte_cfg->entry_type.start,       pte_cfg->entry_type.width,      pte_ptr);
    iprop_field_place(d_attr,          pte_cfg->d_attr.start,           pte_cfg->d_attr.width,          pte_ptr);
    iprop_field_place(space_type,      pte_cfg->space_type.start,       pte_cfg->space_type.width,      pte_ptr);
    iprop_field_place(drc,             pte_cfg->drc.start,              pte_cfg->drc.width,             pte_ptr);
    iprop_field_place(proxy_page,      pte_cfg->proxy_page.start,       pte_cfg->proxy_page.width,      pte_ptr);
    iprop_field_place(cache_coherence, pte_cfg->cache_coherence.start,  pte_cfg->cache_coherence.width, pte_ptr);
    iprop_field_place(cap,             pte_cfg->cap.start,              pte_cfg->cap.width,             pte_ptr);
    iprop_field_place(wp,              pte_cfg->wp.start,               pte_cfg->wp.width,              pte_ptr);
    iprop_field_place(pasid_en,        pte_cfg->pasid_en.start,         pte_cfg->pasid_en.width,        pte_ptr);
    iprop_field_place(pfme_en,         pte_cfg->pfme_en.start,          pte_cfg->pfme_en.width,         pte_ptr);
    iprop_field_place(pec,             pte_cfg->pec.start,              pte_cfg->pec.width,             pte_ptr);
    iprop_field_place(lp_en,           pte_cfg->lp_en.start,            pte_cfg->lp_en.width,           pte_ptr);
    iprop_field_place(ns_en,           pte_cfg->ns_en.start,            pte_cfg->ns_en.width,           pte_ptr);
    iprop_field_place(write_mode,      pte_cfg->write_mode.start,       pte_cfg->write_mode.width,      pte_ptr);
    iprop_field_place(traffic_class,   pte_cfg->traffic_class.start,    pte_cfg->traffic_class.width,   pte_ptr);
    iprop_field_place(passid,          pte_cfg->passid.start,           pte_cfg->passid.width,          pte_ptr);
    iprop_field_place(local_dest,      pte_cfg->local_dest.start,       pte_cfg->local_dest.width,      pte_ptr);
    iprop_field_place(global_dest,     pte_cfg->global_dest.start,      pte_cfg->global_dest.width,     pte_ptr);
    iprop_field_place(tr_index,        pte_cfg->tr_index.start,         pte_cfg->tr_index.width,        pte_ptr);
    iprop_field_place(co,              pte_cfg->co.start,               pte_cfg->co.width,              pte_ptr);
    iprop_field_place(rkey,            pte_cfg->rkey.start,             pte_cfg->rkey.width,            pte_ptr);
    if (drc)
      addr |= ((uint64_t)dr_intf << 40);
    iprop_field_place(addr,            pte_cfg->addr.start,             pte_cfg->addr.width,            pte_ptr);
    //iprop_field_place(dr_intf,         pte_cfg->dr_intf.start,          pte_cfg->dr_intf.width,         pte_ptr);

}


void dump_pte_bit_positions(struct genz_reqr_pte_config * pte_cfg)
{
    printk("pte:: {");
    if (pte_cfg->dr_intf.width)         {printk("dr_intf[%d:%d], ",        pte_cfg->dr_intf.start+        pte_cfg->dr_intf.width-1,      pte_cfg->dr_intf.start);}
    if (pte_cfg->addr.width)            {printk("addr[%d:%d], ",           pte_cfg->addr.start+           pte_cfg->addr.width-1,         pte_cfg->addr.start);}
    if (pte_cfg->rkey.width)            {printk("rkey[%d:%d], ",           pte_cfg->rkey.start+           pte_cfg->rkey.width-1,         pte_cfg->rkey.start);}
    if (pte_cfg->co.width)              {printk("co[%d:%d], ",             pte_cfg->co.start+             pte_cfg->co.width-1,           pte_cfg->co.start);}
    if (pte_cfg->tr_index.width)        {printk("tr_index[%d:%d], ",       pte_cfg->tr_index.start+       pte_cfg->tr_index.width-1,     pte_cfg->tr_index.start);}
    if (pte_cfg->global_dest.width)     {printk("global_dest[%d:%d], ",    pte_cfg->global_dest.start+    pte_cfg->global_dest.width-1,  pte_cfg->global_dest.start);}
    if (pte_cfg->local_dest.width)      {printk("local_dest[%d:%d], ",     pte_cfg->local_dest.start+     pte_cfg->local_dest.width-1,   pte_cfg->local_dest.start);}
    if (pte_cfg->passid.width)          {printk("passid[%d:%d], ",         pte_cfg->passid.start+         pte_cfg->passid.width-1,       pte_cfg->passid.start);}
    if (pte_cfg->traffic_class.width)   {printk("tc[%d:%d], ",             pte_cfg->traffic_class.start+  pte_cfg->traffic_class.width-1,pte_cfg->traffic_class.start);}
    if (pte_cfg->write_mode.width)      {printk("write_mode[%d:%d], ",     pte_cfg->write_mode.start+     pte_cfg->write_mode.width-1,   pte_cfg->write_mode.start);}
    if (pte_cfg->ns_en.width)           {printk("ns[%d:%d], ",             pte_cfg->ns_en.start+          pte_cfg->ns_en.width-1,        pte_cfg->ns_en.start);}
    if (pte_cfg->lp_en.width)           {printk("lp[%d:%d], ",             pte_cfg->lp_en.start+          pte_cfg->lp_en.width-1,        pte_cfg->lp_en.start);}
    if (pte_cfg->pec.width)             {printk("pec[%d:%d], ",            pte_cfg->pec.start+            pte_cfg->pec.width-1,          pte_cfg->pec.start);}
    if (pte_cfg->pfme_en.width)         {printk("pfme_en[%d:%d], ",        pte_cfg->pfme_en.start+        pte_cfg->pfme_en.width-1,      pte_cfg->pfme_en.start);}
    if (pte_cfg->pasid_en.width)        {printk("pasid_en[%d:%d], ",       pte_cfg->pasid_en.start+       pte_cfg->pasid_en.width-1,     pte_cfg->pasid_en.start);}
    if (pte_cfg->wp.width)              {printk("wp[%d:%d], ",             pte_cfg->wp.start+             pte_cfg->wp.width-1,           pte_cfg->wp.start);}
    if (pte_cfg->cap.width)             {printk("cap[%d:%d], ",            pte_cfg->cap.start+            pte_cfg->cap.width-1,          pte_cfg->cap.start);}
    if (pte_cfg->cache_coherence.width) {printk("cache_coherence[%d:%d], ",pte_cfg->cache_coherence.start+pte_cfg->cache_coherence.width-1, pte_cfg->cache_coherence.start);}
    if (pte_cfg->proxy_page.width)      {printk("proxy_page[%d:%d], ",     pte_cfg->proxy_page.start+     pte_cfg->proxy_page.width-1,   pte_cfg->proxy_page.start);}
    if (pte_cfg->drc.width)             {printk("drc[%d:%d], ",            pte_cfg->drc.start+            pte_cfg->drc.width-1,          pte_cfg->drc.start);}
    if (pte_cfg->space_type.width)      {printk("space_type[%d:%d], ",     pte_cfg->space_type.start+     pte_cfg->space_type.width-1,   pte_cfg->space_type.start);}
    if (pte_cfg->d_attr.width)          {printk("d_attr[%d:%d], ",         pte_cfg->d_attr.start+         pte_cfg->d_attr.width-1,       pte_cfg->d_attr.start);}
    if (pte_cfg->entry_type.width)      {printk("entry_type[%d:%d], ",     pte_cfg->entry_type.start+     pte_cfg->entry_type.width-1,   pte_cfg->entry_type.start);}
    if (pte_cfg->valid.width)           {printk("valid[%d:%d]",            pte_cfg->valid.start+          pte_cfg->valid.width-1,        pte_cfg->valid.start);}
    printk("}\n");
}

// Temp and hacky - not flexible for all pte definitions -- TODO:: make flexible for all pte configs
void print_pte(struct genz_reqr_pte_config * pte_cfg, uint32_t * pte_base, uint32_t pte_index, uint16_t pte_width)
{
    uint8_t pte_dw_width = pte_width / 32;
    uint64_t pte__63__0 = ((uint64_t)pte_base[pte_index*pte_dw_width+1] << 32) | (pte_base[pte_index*pte_dw_width]);
    //uint64_t pte_127_64 = ((uint64_t)pte_base[pte_index*pte_dw_width+3] << 32) | (pte_base[pte_index*pte_dw_width+2]);

    //if (pte_cfg->dr_intf.width)         {printk("dr_intf: %lX\n", field_select64(pte__63__0, pte_cfg->dr_intf.start + pte_cfg->dr_intf.width - 1, pte_cfg->dr_intf.start);}

    printk("PTE[%02X]: ---------------------- %d, pte_dw:%d\n", pte_index, pte_width, pte_dw_width);
    printk("{\n");
    if (pte_cfg->addr.width)            {printk("    addr:           %lX\n", field_select64(pte__63__0, 63, pte_cfg->addr.start));}
    if (pte_cfg->rkey.width)            {printk("    rkey:           %lX\n", field_select64(pte__63__0, pte_cfg->rkey.start + pte_cfg->rkey.width - 1,                  pte_cfg->rkey.start));}
    if (pte_cfg->co.width)              {printk("    co:             %lX\n", field_select64(pte__63__0, pte_cfg->co.start + pte_cfg->co.width - 1,                      pte_cfg->co.start));}
    if (pte_cfg->tr_index.width)        {printk("    tr_index:       %lX\n", field_select64(pte__63__0, pte_cfg->tr_index.start + pte_cfg->tr_index.width - 1,          pte_cfg->tr_index.start));}
    if (pte_cfg->global_dest.width)     {printk("    global_dest:    %lX\n", field_select64(pte__63__0, pte_cfg->global_dest.start + pte_cfg->global_dest.width - 1,    pte_cfg->global_dest.start));}
    if (pte_cfg->local_dest.width)      {printk("    local_dest:     %lX\n", field_select64(pte__63__0, pte_cfg->local_dest.start + pte_cfg->local_dest.width - 1,      pte_cfg->local_dest.start));}
    if (pte_cfg->passid.width)          {printk("    passid:         %lX\n", field_select64(pte__63__0, pte_cfg->passid.start + pte_cfg->passid.width - 1,              pte_cfg->passid.start));}
    if (pte_cfg->traffic_class.width)   {printk("    tc:             %lX\n", field_select64(pte__63__0, pte_cfg->traffic_class.start + pte_cfg->traffic_class.width - 1,pte_cfg->traffic_class.start));}
    if (pte_cfg->write_mode.width)      {printk("    write_mode:     %lX\n", field_select64(pte__63__0, pte_cfg->write_mode.start + pte_cfg->write_mode.width - 1,      pte_cfg->write_mode.start));}
    if (pte_cfg->ns_en.width)           {printk("    ns:             %lX\n", field_select64(pte__63__0, pte_cfg->ns_en.start + pte_cfg->ns_en.width - 1,                pte_cfg->ns_en.start));}
    if (pte_cfg->lp_en.width)           {printk("    lp:             %lX\n", field_select64(pte__63__0, pte_cfg->lp_en.start + pte_cfg->lp_en.width - 1,                pte_cfg->lp_en.start));}
    if (pte_cfg->pec.width)             {printk("    pec:            %lX\n", field_select64(pte__63__0, pte_cfg->pec.start + pte_cfg->pec.width - 1,                    pte_cfg->pec.start));}
    if (pte_cfg->pfme_en.width)         {printk("    pfme_en:        %lX\n", field_select64(pte__63__0, pte_cfg->pfme_en.start + pte_cfg->pfme_en.width - 1,            pte_cfg->pfme_en.start));}
    if (pte_cfg->pasid_en.width)        {printk("    pasid_en:       %lX\n", field_select64(pte__63__0, pte_cfg->pasid_en.start + pte_cfg->pasid_en.width - 1,          pte_cfg->pasid_en.start));}
    if (pte_cfg->wp.width)              {printk("    wp:             %lX\n", field_select64(pte__63__0, pte_cfg->wp.start + pte_cfg->wp.width - 1,                      pte_cfg->wp.start));}
    if (pte_cfg->cap.width)             {printk("    cap:            %lX\n", field_select64(pte__63__0, pte_cfg->cap.start + pte_cfg->cap.width - 1,                    pte_cfg->cap.start));}
    if (pte_cfg->cache_coherence.width) {printk("    cache_coherence:%lX\n", field_select64(pte__63__0, pte_cfg->cache_coherence.start + pte_cfg->cache_coherence.width - 1,pte_cfg->cache_coherence.start));}
    if (pte_cfg->proxy_page.width)      {printk("    proxy_page:     %lX\n", field_select64(pte__63__0, pte_cfg->proxy_page.start + pte_cfg->proxy_page.width - 1,      pte_cfg->proxy_page.start));}
    if (pte_cfg->drc.width)             {printk("    drc:            %lX\n", field_select64(pte__63__0, pte_cfg->drc.start + pte_cfg->drc.width - 1,                    pte_cfg->drc.start));}
    if (pte_cfg->space_type.width)      {printk("    space_type:     %lX\n", field_select64(pte__63__0, pte_cfg->space_type.start + pte_cfg->space_type.width - 1,      pte_cfg->space_type.start));}
    if (pte_cfg->d_attr.width)          {printk("    d_attr:         %lX\n", field_select64(pte__63__0, pte_cfg->d_attr.start + pte_cfg->d_attr.width - 1,              pte_cfg->d_attr.start));}
    if (pte_cfg->entry_type.width)      {printk("    entry_type:     %lX\n", field_select64(pte__63__0, pte_cfg->entry_type.start + pte_cfg->entry_type.width - 1,      pte_cfg->entry_type.start));}
    if (pte_cfg->valid.width)           {printk("    valid:          %lX\n", field_select64(pte__63__0, pte_cfg->valid.start + pte_cfg->valid.width - 1,                pte_cfg->valid.start));}
    printk("}\n");
}


void iprop_genz_calc_pte_width(struct genz_component_page_grid_structure * const gz_cpgs, struct genz_reqr_pte_config * pte_cfg)
{

    struct genz_reqr_pte_attr_63_00field * pte_attr = (struct genz_reqr_pte_attr_63_00field *)&gz_cpgs->pte_attr_63_0;
    uint16_t valid_bits  = 0;

    pte_cfg->valid.start = 0;
    pte_cfg->valid.width = 1;
    valid_bits += 1;                                         // Valid bit

    pte_cfg->entry_type.width = 0;
    pte_cfg->entry_type.start = valid_bits;
    valid_bits += 0;                                         // ET only valid for page table based entry type

    pte_cfg->d_attr.width = 3;
    pte_cfg->d_attr.start = valid_bits;
    valid_bits += 3;                                         // d-attr

    pte_cfg->space_type.width = pte_attr->st_drc_support;
    pte_cfg->space_type.start = valid_bits;
    valid_bits += pte_attr->st_drc_support;                  // Space Type

    pte_cfg->drc.width = pte_attr->st_drc_support;
    pte_cfg->drc.start = valid_bits;
    valid_bits += pte_attr->st_drc_support;                  // Directed Relay Control

    pte_cfg->proxy_page.width = 0;
    pte_cfg->proxy_page.start = valid_bits;
    valid_bits += 0;                                         // Data Space PTE: Proxy Page (TODO:: Check RTL)

    pte_cfg->cache_coherence.width = pte_attr->cce_support;
    pte_cfg->cache_coherence.start = valid_bits;
    valid_bits += pte_attr->cce_support;                     // Cache Coherency Enable

    pte_cfg->cap.width = pte_attr->ce_support;
    pte_cfg->cap.start = valid_bits;
    valid_bits += pte_attr->ce_support;                      // Capabilities Enable

    pte_cfg->wp.width = pte_attr->wpe_support;
    pte_cfg->wp.start = valid_bits;
    valid_bits += pte_attr->wpe_support;                     // Write Poison Enable

    pte_cfg->pasid_en.width = (pte_attr->passid_sz > 0) ? 1 : 0;
    pte_cfg->pasid_en.start = valid_bits;
    valid_bits += (pte_attr->passid_sz > 0) ? 1 : 0;         // PASID Enable

    pte_cfg->pfme_en.width = pte_attr->pfme_support;
    pte_cfg->pfme_en.start = valid_bits;
    valid_bits += pte_attr->pfme_support;                    // Performance Marker (PM) Enable

    pte_cfg->pec.width = pte_attr->pec_support;
    pte_cfg->pec.start = valid_bits;
    valid_bits += pte_attr->pec_support;                     // Processor Exception Control

    pte_cfg->lp_en.width = pte_attr->lpe_support;
    pte_cfg->lp_en.start = valid_bits;
    valid_bits += pte_attr->lpe_support;                     // LP Enable

    pte_cfg->ns_en.width = pte_attr->nse_support;
    pte_cfg->ns_en.start = valid_bits;
    valid_bits += pte_attr->nse_support;                     // No-Snoop Enable

    pte_cfg->write_mode.width = 3;
    pte_cfg->write_mode.start = valid_bits;
    valid_bits += 3;                                         // Write Mode

    pte_cfg->traffic_class.width = (pte_attr->traffic_class_support) ? 4 : 0;
    pte_cfg->traffic_class.start = valid_bits;
    valid_bits += (pte_attr->traffic_class_support) ? 4 : 0; // Traffic Class

    pte_cfg->passid.width = pte_attr->passid_sz;
    pte_cfg->passid.start = valid_bits;
    valid_bits += pte_attr->passid_sz;                       // PASID

    pte_cfg->local_dest.width = 12;
    pte_cfg->local_dest.start = valid_bits;
    valid_bits += 12;                                        // Local Destination

    pte_cfg->global_dest.width = pte_attr->pte_gd_sz;
    pte_cfg->global_dest.start = valid_bits;
    valid_bits += pte_attr->pte_gd_sz;                       // Global Destination

    pte_cfg->tr_index.width = (pte_attr->tr_index_support) ? 4 : 0;
    pte_cfg->tr_index.start = valid_bits;
    valid_bits += (pte_attr->tr_index_support) ? 4 : 0;      // Transparent Router Support

    pte_cfg->co.width = (pte_attr->co_support) ? 2 : 0;
    pte_cfg->co.start = valid_bits;
    valid_bits += (pte_attr->co_support) ? 2 : 0;            // Component is a Transparent Router and the Requester in one subnet and responder in another do not support common OpClass

    pte_cfg->rkey.width = (pte_attr->rkey_field_support) ? 32 : 0;
    pte_cfg->rkey.start = valid_bits;
    valid_bits += (pte_attr->rkey_field_support) ? 32 : 0;   // Region Key Support

    pte_cfg->addr.width = 52;
    pte_cfg->addr.start = valid_bits;
    valid_bits += 52;                                        // address

    //pte_cfg->dr_intf.width = (pte_attr->st_drc_support) ? 12 : 0;
    //pte_cfg->dr_intf.start = valid_bits;
    //valid_bits += (pte_attr->st_drc_support) ? 12 : 0;       // Switch egress interface identifier

    pte_cfg->pte_field_width = valid_bits;

}

//void iprop_genz_con_init_page_grid(struct genz_page_grid_restricted_page_grid_table_array * const gz_pg,
//                                   uint16_t pg_entry,
//                                   uint64_t pg_base_addr,
//                                   uint8_t  page_size,
//                                   uint32_t page_count,
//                                   uint8_t  restricted_access,
//                                   uint32_t base_pte_index)
//{
//    gz_pg[pg_entry].pg_base_address_0 = pg_base_addr >> 12;
//    gz_pg[pg_entry].page_size_0       = page_size;
//    gz_pg[pg_entry].page_count_0      = page_count;
//    gz_pg[pg_entry].res               = (restricted_access & 1);
//    gz_pg[pg_entry].base_pte_index_0  = base_pte_index;
//}
//
//void iprop_genz_con_dump_page_grid(struct genz_page_grid_restricted_page_grid_table_array * const gz_pg, uint16_t pg_entry)
//{
//    uint64_t * addr   = (uint64_t*)&gz_pg[pg_entry];
//    printk("pg_entry[%04X]: addr of pg entry 0x%016lX\n", pg_entry, (uint64_t)addr);
//    uint64_t val_low  = *addr++;
//    uint64_t val_high = *addr;
//    printk("pg_entry[%04X]: raw              0x%016lX %016lX\n", pg_entry, val_high, val_low);
//    printk("pg_entry[%04X]: pg_base_address: 0x%016lX\n",    pg_entry, (uint64_t)(gz_pg[pg_entry].pg_base_address_0) << 12);
//    printk("pg_entry[%04X]: page_size:       0x%016lX\n",    pg_entry, (uint64_t)1 << gz_pg[pg_entry].page_size_0);
//    printk("pg_entry[%04X]: page_count:      0x%06X\n",      pg_entry,  gz_pg[pg_entry].page_count_0);
//    printk("pg_entry[%04X]: res:             0x%X\n",        pg_entry,  gz_pg[pg_entry].res);
//    printk("pg_entry[%04X]: base_pte_index:  0x%08X\n",      pg_entry,  gz_pg[pg_entry].base_pte_index_0);
//}

void iprop_field_place(uint64_t field, uint16_t field_start_bit, uint8_t field_width, uint8_t * struct_base)
{
    if (field_width == 0) {
        // nothing to do here...
        return;
    }
    // calculate the number of bits from the field_start_bit to the end of the first byte
    uint8_t  const dist_to_byte_end   = (8 - (field_start_bit & 7));
    // calculate the number of valid bits in the first byte
    uint8_t  const first_n_valid_bits = field_width >= dist_to_byte_end ?  dist_to_byte_end : field_width;
    // calculate the byte index into the structure
    uint16_t cur_byte_offset    = field_start_bit / 8;

    // starting mask w/o consideration of width
    uint16_t start_byte_valid_mask = (1 << (8 - field_start_bit % 8))-1;

    if (field_width < (8 - (field_start_bit & 7))) {
        start_byte_valid_mask >>= (8 - (field_start_bit & 7)) - field_width;
    }
    start_byte_valid_mask <<= field_start_bit & 7;

    // Read Modify Write the first Byte
    uint8_t rmw = struct_base[cur_byte_offset];
    rmw &= ~start_byte_valid_mask;
    rmw |=  (field << (field_start_bit & 7)) & start_byte_valid_mask;
    struct_base[cur_byte_offset++] = rmw;

    field_width  -= first_n_valid_bits;
    field       >>= first_n_valid_bits;

    // Lay down the remaining byte(s) within the field
    while (field_width) {
        if (field_width > 8) {
            struct_base[cur_byte_offset] = (field & 0xFF);
            field >>= 8;
            field_width -= 8;
        } else {
            const uint8_t last_mask = (1 << field_width) - 1;
            struct_base[cur_byte_offset] = field & last_mask;
            field_width = 0;
        }
        cur_byte_offset++;
    }
}

uint64_t field_select64(uint64_t qw, uint8_t upper_bit, uint8_t lower_bit)
{
    uint64_t mask = 0xFFFFFFFFFFFFFFFFULL >> (63 - (upper_bit - lower_bit));
             mask <<= lower_bit;
    return (qw & mask) >> lower_bit;
}

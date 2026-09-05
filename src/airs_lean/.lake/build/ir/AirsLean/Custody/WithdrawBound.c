// Lean compiler output
// Module: AirsLean.Custody.WithdrawBound
// Imports: public import Init public meta import Init public import AirsLean.Custody.ExitControl
#include <lean/lean.h>
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-label"
#elif defined(__GNUC__) && !defined(__CLANG__)
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-label"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif
#ifdef __cplusplus
extern "C" {
#endif
lean_object* lean_nat_add(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_ctorIdx(lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_ctorIdx___boxed(lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_ctorElim___redArg(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_ctorElim(lean_object*, lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_ctorElim___boxed(lean_object*, lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_idle_elim___redArg(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_idle_elim(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_funding_elim___redArg(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_funding_elim(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_award_elim___redArg(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_award_elim(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_merge_elim___redArg(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_merge_elim(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_payout_elim___redArg(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_payout_elim(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_ledgerStep(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_ledgerStep___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_chainLedger(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_chainLedger___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean___private_AirsLean_Custody_WithdrawBound_0__AirsLean_ChainOk_match__1_splitter___redArg(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean___private_AirsLean_Custody_WithdrawBound_0__AirsLean_ChainOk_match__1_splitter(lean_object*, lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_ctorIdx(lean_object* v_x_1_){
_start:
{
switch(lean_obj_tag(v_x_1_))
{
case 0:
{
lean_object* v___x_2_; 
v___x_2_ = lean_unsigned_to_nat(0u);
return v___x_2_;
}
case 1:
{
lean_object* v___x_3_; 
v___x_3_ = lean_unsigned_to_nat(1u);
return v___x_3_;
}
case 2:
{
lean_object* v___x_4_; 
v___x_4_ = lean_unsigned_to_nat(2u);
return v___x_4_;
}
case 3:
{
lean_object* v___x_5_; 
v___x_5_ = lean_unsigned_to_nat(3u);
return v___x_5_;
}
default: 
{
lean_object* v___x_6_; 
v___x_6_ = lean_unsigned_to_nat(4u);
return v___x_6_;
}
}
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_ctorIdx___boxed(lean_object* v_x_7_){
_start:
{
lean_object* v_res_8_; 
v_res_8_ = lp_airs__lean_AirsLean_PStep_ctorIdx(v_x_7_);
lean_dec(v_x_7_);
return v_res_8_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_ctorElim___redArg(lean_object* v_t_9_, lean_object* v_k_10_){
_start:
{
if (lean_obj_tag(v_t_9_) == 0)
{
return v_k_10_;
}
else
{
lean_object* v_a_11_; lean_object* v___x_12_; 
v_a_11_ = lean_ctor_get(v_t_9_, 0);
lean_inc(v_a_11_);
lean_dec(v_t_9_);
v___x_12_ = lean_apply_1(v_k_10_, v_a_11_);
return v___x_12_;
}
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_ctorElim(lean_object* v_motive_13_, lean_object* v_ctorIdx_14_, lean_object* v_t_15_, lean_object* v_h_16_, lean_object* v_k_17_){
_start:
{
lean_object* v___x_18_; 
v___x_18_ = lp_airs__lean_AirsLean_PStep_ctorElim___redArg(v_t_15_, v_k_17_);
return v___x_18_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_ctorElim___boxed(lean_object* v_motive_19_, lean_object* v_ctorIdx_20_, lean_object* v_t_21_, lean_object* v_h_22_, lean_object* v_k_23_){
_start:
{
lean_object* v_res_24_; 
v_res_24_ = lp_airs__lean_AirsLean_PStep_ctorElim(v_motive_19_, v_ctorIdx_20_, v_t_21_, v_h_22_, v_k_23_);
lean_dec(v_ctorIdx_20_);
return v_res_24_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_idle_elim___redArg(lean_object* v_t_25_, lean_object* v_idle_26_){
_start:
{
lean_object* v___x_27_; 
v___x_27_ = lp_airs__lean_AirsLean_PStep_ctorElim___redArg(v_t_25_, v_idle_26_);
return v___x_27_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_idle_elim(lean_object* v_motive_28_, lean_object* v_t_29_, lean_object* v_h_30_, lean_object* v_idle_31_){
_start:
{
lean_object* v___x_32_; 
v___x_32_ = lp_airs__lean_AirsLean_PStep_ctorElim___redArg(v_t_29_, v_idle_31_);
return v___x_32_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_funding_elim___redArg(lean_object* v_t_33_, lean_object* v_funding_34_){
_start:
{
lean_object* v___x_35_; 
v___x_35_ = lp_airs__lean_AirsLean_PStep_ctorElim___redArg(v_t_33_, v_funding_34_);
return v___x_35_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_funding_elim(lean_object* v_motive_36_, lean_object* v_t_37_, lean_object* v_h_38_, lean_object* v_funding_39_){
_start:
{
lean_object* v___x_40_; 
v___x_40_ = lp_airs__lean_AirsLean_PStep_ctorElim___redArg(v_t_37_, v_funding_39_);
return v___x_40_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_award_elim___redArg(lean_object* v_t_41_, lean_object* v_award_42_){
_start:
{
lean_object* v___x_43_; 
v___x_43_ = lp_airs__lean_AirsLean_PStep_ctorElim___redArg(v_t_41_, v_award_42_);
return v___x_43_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_award_elim(lean_object* v_motive_44_, lean_object* v_t_45_, lean_object* v_h_46_, lean_object* v_award_47_){
_start:
{
lean_object* v___x_48_; 
v___x_48_ = lp_airs__lean_AirsLean_PStep_ctorElim___redArg(v_t_45_, v_award_47_);
return v___x_48_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_merge_elim___redArg(lean_object* v_t_49_, lean_object* v_merge_50_){
_start:
{
lean_object* v___x_51_; 
v___x_51_ = lp_airs__lean_AirsLean_PStep_ctorElim___redArg(v_t_49_, v_merge_50_);
return v___x_51_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_merge_elim(lean_object* v_motive_52_, lean_object* v_t_53_, lean_object* v_h_54_, lean_object* v_merge_55_){
_start:
{
lean_object* v___x_56_; 
v___x_56_ = lp_airs__lean_AirsLean_PStep_ctorElim___redArg(v_t_53_, v_merge_55_);
return v___x_56_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_payout_elim___redArg(lean_object* v_t_57_, lean_object* v_payout_58_){
_start:
{
lean_object* v___x_59_; 
v___x_59_ = lp_airs__lean_AirsLean_PStep_ctorElim___redArg(v_t_57_, v_payout_58_);
return v___x_59_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_PStep_payout_elim(lean_object* v_motive_60_, lean_object* v_t_61_, lean_object* v_h_62_, lean_object* v_payout_63_){
_start:
{
lean_object* v___x_64_; 
v___x_64_ = lp_airs__lean_AirsLean_PStep_ctorElim___redArg(v_t_61_, v_payout_63_);
return v___x_64_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_ledgerStep(lean_object* v_x_65_, lean_object* v_x_66_){
_start:
{
switch(lean_obj_tag(v_x_65_))
{
case 0:
{
return v_x_66_;
}
case 1:
{
lean_object* v_a_67_; lean_object* v_dep_68_; lean_object* v_paid_69_; lean_object* v_merged_70_; lean_object* v_awards_71_; lean_object* v___x_73_; uint8_t v_isShared_74_; uint8_t v_isSharedCheck_79_; 
v_a_67_ = lean_ctor_get(v_x_65_, 0);
v_dep_68_ = lean_ctor_get(v_x_66_, 0);
v_paid_69_ = lean_ctor_get(v_x_66_, 1);
v_merged_70_ = lean_ctor_get(v_x_66_, 2);
v_awards_71_ = lean_ctor_get(v_x_66_, 3);
v_isSharedCheck_79_ = !lean_is_exclusive(v_x_66_);
if (v_isSharedCheck_79_ == 0)
{
v___x_73_ = v_x_66_;
v_isShared_74_ = v_isSharedCheck_79_;
goto v_resetjp_72_;
}
else
{
lean_inc(v_awards_71_);
lean_inc(v_merged_70_);
lean_inc(v_paid_69_);
lean_inc(v_dep_68_);
lean_dec(v_x_66_);
v___x_73_ = lean_box(0);
v_isShared_74_ = v_isSharedCheck_79_;
goto v_resetjp_72_;
}
v_resetjp_72_:
{
lean_object* v___x_75_; lean_object* v___x_77_; 
v___x_75_ = lean_nat_add(v_dep_68_, v_a_67_);
lean_dec(v_dep_68_);
if (v_isShared_74_ == 0)
{
lean_ctor_set(v___x_73_, 0, v___x_75_);
v___x_77_ = v___x_73_;
goto v_reusejp_76_;
}
else
{
lean_object* v_reuseFailAlloc_78_; 
v_reuseFailAlloc_78_ = lean_alloc_ctor(0, 4, 0);
lean_ctor_set(v_reuseFailAlloc_78_, 0, v___x_75_);
lean_ctor_set(v_reuseFailAlloc_78_, 1, v_paid_69_);
lean_ctor_set(v_reuseFailAlloc_78_, 2, v_merged_70_);
lean_ctor_set(v_reuseFailAlloc_78_, 3, v_awards_71_);
v___x_77_ = v_reuseFailAlloc_78_;
goto v_reusejp_76_;
}
v_reusejp_76_:
{
return v___x_77_;
}
}
}
case 2:
{
lean_object* v_a_80_; lean_object* v_dep_81_; lean_object* v_paid_82_; lean_object* v_merged_83_; lean_object* v_awards_84_; lean_object* v___x_86_; uint8_t v_isShared_87_; uint8_t v_isSharedCheck_92_; 
v_a_80_ = lean_ctor_get(v_x_65_, 0);
v_dep_81_ = lean_ctor_get(v_x_66_, 0);
v_paid_82_ = lean_ctor_get(v_x_66_, 1);
v_merged_83_ = lean_ctor_get(v_x_66_, 2);
v_awards_84_ = lean_ctor_get(v_x_66_, 3);
v_isSharedCheck_92_ = !lean_is_exclusive(v_x_66_);
if (v_isSharedCheck_92_ == 0)
{
v___x_86_ = v_x_66_;
v_isShared_87_ = v_isSharedCheck_92_;
goto v_resetjp_85_;
}
else
{
lean_inc(v_awards_84_);
lean_inc(v_merged_83_);
lean_inc(v_paid_82_);
lean_inc(v_dep_81_);
lean_dec(v_x_66_);
v___x_86_ = lean_box(0);
v_isShared_87_ = v_isSharedCheck_92_;
goto v_resetjp_85_;
}
v_resetjp_85_:
{
lean_object* v___x_88_; lean_object* v___x_90_; 
v___x_88_ = lean_nat_add(v_awards_84_, v_a_80_);
lean_dec(v_awards_84_);
if (v_isShared_87_ == 0)
{
lean_ctor_set(v___x_86_, 3, v___x_88_);
v___x_90_ = v___x_86_;
goto v_reusejp_89_;
}
else
{
lean_object* v_reuseFailAlloc_91_; 
v_reuseFailAlloc_91_ = lean_alloc_ctor(0, 4, 0);
lean_ctor_set(v_reuseFailAlloc_91_, 0, v_dep_81_);
lean_ctor_set(v_reuseFailAlloc_91_, 1, v_paid_82_);
lean_ctor_set(v_reuseFailAlloc_91_, 2, v_merged_83_);
lean_ctor_set(v_reuseFailAlloc_91_, 3, v___x_88_);
v___x_90_ = v_reuseFailAlloc_91_;
goto v_reusejp_89_;
}
v_reusejp_89_:
{
return v___x_90_;
}
}
}
case 3:
{
lean_object* v_a_93_; lean_object* v_dep_94_; lean_object* v_paid_95_; lean_object* v_merged_96_; lean_object* v_awards_97_; lean_object* v___x_99_; uint8_t v_isShared_100_; uint8_t v_isSharedCheck_105_; 
v_a_93_ = lean_ctor_get(v_x_65_, 0);
v_dep_94_ = lean_ctor_get(v_x_66_, 0);
v_paid_95_ = lean_ctor_get(v_x_66_, 1);
v_merged_96_ = lean_ctor_get(v_x_66_, 2);
v_awards_97_ = lean_ctor_get(v_x_66_, 3);
v_isSharedCheck_105_ = !lean_is_exclusive(v_x_66_);
if (v_isSharedCheck_105_ == 0)
{
v___x_99_ = v_x_66_;
v_isShared_100_ = v_isSharedCheck_105_;
goto v_resetjp_98_;
}
else
{
lean_inc(v_awards_97_);
lean_inc(v_merged_96_);
lean_inc(v_paid_95_);
lean_inc(v_dep_94_);
lean_dec(v_x_66_);
v___x_99_ = lean_box(0);
v_isShared_100_ = v_isSharedCheck_105_;
goto v_resetjp_98_;
}
v_resetjp_98_:
{
lean_object* v___x_101_; lean_object* v___x_103_; 
v___x_101_ = lean_nat_add(v_merged_96_, v_a_93_);
lean_dec(v_merged_96_);
if (v_isShared_100_ == 0)
{
lean_ctor_set(v___x_99_, 2, v___x_101_);
v___x_103_ = v___x_99_;
goto v_reusejp_102_;
}
else
{
lean_object* v_reuseFailAlloc_104_; 
v_reuseFailAlloc_104_ = lean_alloc_ctor(0, 4, 0);
lean_ctor_set(v_reuseFailAlloc_104_, 0, v_dep_94_);
lean_ctor_set(v_reuseFailAlloc_104_, 1, v_paid_95_);
lean_ctor_set(v_reuseFailAlloc_104_, 2, v___x_101_);
lean_ctor_set(v_reuseFailAlloc_104_, 3, v_awards_97_);
v___x_103_ = v_reuseFailAlloc_104_;
goto v_reusejp_102_;
}
v_reusejp_102_:
{
return v___x_103_;
}
}
}
default: 
{
lean_object* v_a_106_; lean_object* v_dep_107_; lean_object* v_paid_108_; lean_object* v_merged_109_; lean_object* v_awards_110_; lean_object* v___x_112_; uint8_t v_isShared_113_; uint8_t v_isSharedCheck_118_; 
v_a_106_ = lean_ctor_get(v_x_65_, 0);
v_dep_107_ = lean_ctor_get(v_x_66_, 0);
v_paid_108_ = lean_ctor_get(v_x_66_, 1);
v_merged_109_ = lean_ctor_get(v_x_66_, 2);
v_awards_110_ = lean_ctor_get(v_x_66_, 3);
v_isSharedCheck_118_ = !lean_is_exclusive(v_x_66_);
if (v_isSharedCheck_118_ == 0)
{
v___x_112_ = v_x_66_;
v_isShared_113_ = v_isSharedCheck_118_;
goto v_resetjp_111_;
}
else
{
lean_inc(v_awards_110_);
lean_inc(v_merged_109_);
lean_inc(v_paid_108_);
lean_inc(v_dep_107_);
lean_dec(v_x_66_);
v___x_112_ = lean_box(0);
v_isShared_113_ = v_isSharedCheck_118_;
goto v_resetjp_111_;
}
v_resetjp_111_:
{
lean_object* v___x_114_; lean_object* v___x_116_; 
v___x_114_ = lean_nat_add(v_paid_108_, v_a_106_);
lean_dec(v_paid_108_);
if (v_isShared_113_ == 0)
{
lean_ctor_set(v___x_112_, 1, v___x_114_);
v___x_116_ = v___x_112_;
goto v_reusejp_115_;
}
else
{
lean_object* v_reuseFailAlloc_117_; 
v_reuseFailAlloc_117_ = lean_alloc_ctor(0, 4, 0);
lean_ctor_set(v_reuseFailAlloc_117_, 0, v_dep_107_);
lean_ctor_set(v_reuseFailAlloc_117_, 1, v___x_114_);
lean_ctor_set(v_reuseFailAlloc_117_, 2, v_merged_109_);
lean_ctor_set(v_reuseFailAlloc_117_, 3, v_awards_110_);
v___x_116_ = v_reuseFailAlloc_117_;
goto v_reusejp_115_;
}
v_reusejp_115_:
{
return v___x_116_;
}
}
}
}
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_ledgerStep___boxed(lean_object* v_x_119_, lean_object* v_x_120_){
_start:
{
lean_object* v_res_121_; 
v_res_121_ = lp_airs__lean_AirsLean_ledgerStep(v_x_119_, v_x_120_);
lean_dec(v_x_119_);
return v_res_121_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_chainLedger(lean_object* v_x_122_, lean_object* v_x_123_){
_start:
{
if (lean_obj_tag(v_x_122_) == 0)
{
return v_x_123_;
}
else
{
lean_object* v_head_124_; lean_object* v_tail_125_; lean_object* v___x_126_; 
v_head_124_ = lean_ctor_get(v_x_122_, 0);
v_tail_125_ = lean_ctor_get(v_x_122_, 1);
v___x_126_ = lp_airs__lean_AirsLean_ledgerStep(v_head_124_, v_x_123_);
v_x_122_ = v_tail_125_;
v_x_123_ = v___x_126_;
goto _start;
}
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_chainLedger___boxed(lean_object* v_x_128_, lean_object* v_x_129_){
_start:
{
lean_object* v_res_130_; 
v_res_130_ = lp_airs__lean_AirsLean_chainLedger(v_x_128_, v_x_129_);
lean_dec(v_x_128_);
return v_res_130_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean___private_AirsLean_Custody_WithdrawBound_0__AirsLean_ChainOk_match__1_splitter___redArg(lean_object* v_x_131_, lean_object* v_x_132_, lean_object* v_h__1_133_, lean_object* v_h__2_134_){
_start:
{
if (lean_obj_tag(v_x_131_) == 0)
{
lean_object* v___x_135_; 
lean_dec(v_h__2_134_);
v___x_135_ = lean_apply_1(v_h__1_133_, v_x_132_);
return v___x_135_;
}
else
{
lean_object* v_head_136_; lean_object* v_tail_137_; lean_object* v___x_138_; 
lean_dec(v_h__1_133_);
v_head_136_ = lean_ctor_get(v_x_131_, 0);
lean_inc(v_head_136_);
v_tail_137_ = lean_ctor_get(v_x_131_, 1);
lean_inc(v_tail_137_);
lean_dec_ref_known(v_x_131_, 2);
v___x_138_ = lean_apply_3(v_h__2_134_, v_head_136_, v_tail_137_, v_x_132_);
return v___x_138_;
}
}
}
LEAN_EXPORT lean_object* lp_airs__lean___private_AirsLean_Custody_WithdrawBound_0__AirsLean_ChainOk_match__1_splitter(lean_object* v_motive_139_, lean_object* v_x_140_, lean_object* v_x_141_, lean_object* v_h__1_142_, lean_object* v_h__2_143_){
_start:
{
if (lean_obj_tag(v_x_140_) == 0)
{
lean_object* v___x_144_; 
lean_dec(v_h__2_143_);
v___x_144_ = lean_apply_1(v_h__1_142_, v_x_141_);
return v___x_144_;
}
else
{
lean_object* v_head_145_; lean_object* v_tail_146_; lean_object* v___x_147_; 
lean_dec(v_h__1_142_);
v_head_145_ = lean_ctor_get(v_x_140_, 0);
lean_inc(v_head_145_);
v_tail_146_ = lean_ctor_get(v_x_140_, 1);
lean_inc(v_tail_146_);
lean_dec_ref_known(v_x_140_, 2);
v___x_147_ = lean_apply_3(v_h__2_143_, v_head_145_, v_tail_146_, v_x_141_);
return v___x_147_;
}
}
}
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_airs__lean_AirsLean_Custody_ExitControl(uint8_t builtin);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_airs__lean_AirsLean_Custody_WithdrawBound(uint8_t builtin) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_airs__lean_AirsLean_Custody_ExitControl(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif

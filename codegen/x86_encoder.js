const asmdb = require("asmdb");
const x86 = new asmdb.x86util.X86DataBase().addDefault();

const hexByte = (value) => `0x${value.toString(16).padStart(2, '0')}`;

function toCamel(str) {
  return str.replace(/[^a-z0-9]+/gi, '_');
}

const registers = [
  { r64: 'rax', r32: 'eax', r16: 'ax', r8: 'al', aliases: ['x0'], encoding: 0 },
  { r64: 'rcx', r32: 'ecx', r16: 'cx', r8: 'cl', aliases: ['x1'], encoding: 1 },
  { r64: 'rdx', r32: 'edx', r16: 'dx', r8: 'dl', aliases: ['x2'], encoding: 2 },
  { r64: 'rbx', r32: 'ebx', r16: 'bx', r8: 'bl', aliases: ['x3'], encoding: 3 },
  { r64: 'rsp', r32: 'esp', r16: 'sp', r8: 'spl', aliases: [], encoding: 4 },
  { r64: 'rbp', r32: 'ebp', r16: 'bp', r8: 'bpl', aliases: [], encoding: 5 },
  { r64: 'rsi', r32: 'esi', r16: 'si', r8: 'sil', aliases: [], encoding: 6 },
  { r64: 'rdi', r32: 'edi', r16: 'di', r8: 'dil', aliases: [], encoding: 7 },
  { r64: 'r8',  r32: 'r8d', r16: 'r8w', r8: 'r8b', aliases: [], encoding: 8 },
  { r64: 'r9',  r32: 'r9d', r16: 'r9w', r8: 'r9b', aliases: [], encoding: 9 },
  { r64: 'r10', r32: 'r10d', r16: 'r10w', r8: 'r10b', aliases: [], encoding: 10 },
  { r64: 'r11', r32: 'r11d', r16: 'r11w', r8: 'r11b', aliases: [], encoding: 11 },
  { r64: 'r12', r32: 'r12d', r16: 'r12w', r8: 'r12b', aliases: [], encoding: 12 },
  { r64: 'r13', r32: 'r13d', r16: 'r13w', r8: 'r13b', aliases: [], encoding: 13 },
  { r64: 'r14', r32: 'r14d', r16: 'r14w', r8: 'r14b', aliases: [], encoding: 14 },
  { r64: 'r15', r32: 'r15d', r16: 'r15w', r8: 'r15b', aliases: [], encoding: 15 }
];

const SUPPORTED_MNEMONICS = [
  'nop', 'ret',
  'add', 'sub', 'cmp', 'adc', 'sbb',
  'and', 'or', 'xor',
  'mov', 'test', 'lea',
  'movsx', 'movzx',
  'imul', 'mul', 'div', 'idiv',
  'not', 'neg',
  'inc', 'dec',
  'bt', 'bts', 'btr', 'btc', 'bsf', 'bsr', 'bswap',
  'xchg', 'xadd', 'cmpxchg', 'cmpxchg8b', 'cmpxchg16b',
  'movsb', 'movsw', 'movsq',
  'cmpsb', 'cmpsw', 'cmpsq',
  'scasb', 'scasw', 'scasd', 'scasq',
  'stosb', 'stosw', 'stosd', 'stosq',
  'lodsb', 'lodsw', 'lodsd', 'lodsq',
  'call', 'jmp',
  'push', 'pop',
  'shl', 'shr', 'sar', 'rol', 'ror',
  'jo', 'jno', 'jb', 'jnb', 'jz', 'jnz',
  'jbe', 'ja', 'js', 'jns', 'jp', 'jnp',
  'jl', 'jge', 'jle', 'jg',
  'loop', 'loope', 'loopne',
  'enter', 'leave',
  'shld', 'shrd',
  'cbw', 'cwde', 'cdqe', 'cwd', 'cdq', 'cqo',
  'clc', 'cld', 'cmc', 'lahf', 'popf', 'pushf', 'sahf', 'stc', 'std', 'sti', 'cli',
  'lfence', 'mfence', 'sfence',
  'lzcnt', 'popcnt', 'tzcnt',
  'movbe',
  'cpuid', 'rdtsc', 'rdtscp',
  'pause', 'int3', 'ud2',
  'cmovo', 'cmovno', 'cmovb', 'cmovc', 'cmovnae', 'cmovnb', 'cmovae', 'cmovnc',
  'cmove', 'cmovz', 'cmovne', 'cmovnz', 'cmovbe', 'cmovna', 'cmova', 'cmovnbe',
  'cmovs', 'cmovns', 'cmovp', 'cmovpe', 'cmovnp', 'cmovpo',
  'cmovl', 'cmovnge', 'cmovge', 'cmovnl', 'cmovle', 'cmovng', 'cmovg', 'cmovnle',
  'seto', 'setno', 'setb', 'setc', 'setnae', 'setnb', 'setae', 'setnc',
  'sete', 'setz', 'setne', 'setnz', 'setbe', 'setna', 'seta', 'setnbe',
  'sets', 'setns', 'setp', 'setpe', 'setnp', 'setpo',
  'setl', 'setnge', 'setge', 'setnl', 'setle', 'setng', 'setg', 'setnle',
  'addps', 'addpd', 'subps', 'subpd', 'mulps', 'mulpd', 'divps', 'divpd',
  'andps', 'andpd', 'orps', 'orpd', 'xorps', 'xorpd',
  'movss', 'movsd', 'movups', 'movupd', 'movdqu', 'movaps',
  'paddb', 'paddw', 'paddd', 'paddq', 'psubb', 'psubw', 'psubd', 'psubq',
  'pand', 'por', 'pxor',
  'vaddps', 'vaddpd', 'vaddss', 'vaddsd',
  'vsubps', 'vsubpd', 'vsubss', 'vsubsd',
  'vmulps', 'vmulpd', 'vmulss', 'vmulsd',
  'vdivps', 'vdivpd', 'vdivss', 'vdivsd',
  'vminps', 'vminpd', 'vminss', 'vminsd',
  'vmaxps', 'vmaxpd', 'vmaxss', 'vmaxsd',
  'vsqrtps', 'vsqrtpd', 'vsqrtss', 'vsqrtsd',
  'vrsqrtps', 'vrsqrtss', 'vrcpps', 'vrcpss',
  'vroundps', 'vroundpd', 'vroundss', 'vroundsd',
  'vandps', 'vandpd', 'vandnps', 'vandnpd',
  'vorps', 'vorpd', 'vxorps', 'vxorpd',
  'vmovss', 'vmovsd', 'vmovaps', 'vmovapd', 'vmovups', 'vmovupd',
  'vmovdqa', 'vmovdqu', 'vmovdqa32', 'vmovdqa64', 'vmovdqu32', 'vmovdqu64',
  'vmovd', 'vmovq', 'vmovhlps', 'vmovlhps', 'vmovhps', 'vmovlps', 'vmovhpd', 'vmovlpd',
  'vmovddup', 'vmovshdup', 'vmovsldup',
  'vbroadcastss', 'vbroadcastsd', 'vbroadcastf128', 'vbroadcasti128',
  'vbroadcastf32x2', 'vbroadcastf32x4', 'vbroadcastf64x2', 'vbroadcastf64x4',
  'vbroadcasti32x2', 'vbroadcasti32x4', 'vbroadcasti64x2', 'vbroadcasti64x4',
  'vpermilps', 'vpermilpd', 'vperm2f128', 'vperm2i128',
  'vpermd', 'vpermps', 'vpermq', 'vpermpd',
  'vpermb', 'vpermw', 'vpermi2b', 'vpermi2w', 'vpermi2d', 'vpermi2q',
  'vpermi2ps', 'vpermi2pd', 'vpermt2b', 'vpermt2w', 'vpermt2d', 'vpermt2q',
  'vshufps', 'vshufpd', 'vshuff32x4', 'vshuff64x2', 'vshufi32x4', 'vshufi64x2',
  'vblendps', 'vblendpd', 'vblendvps', 'vblendvpd',
  'vpblendw', 'vpblendd', 'vpblendmb', 'vpblendmw', 'vpblendmd', 'vpblendmq',
  'vextractf128', 'vextracti128', 'vextractf32x4', 'vextractf64x2',
  'vextracti32x4', 'vextracti64x2', 'vextractf32x8', 'vextracti32x8',
  'vextractps', 'vinsertf128', 'vinserti128', 'vinsertf32x4', 'vinsertf64x2',
  'vinserti32x4', 'vinserti64x2', 'vinsertf32x8', 'vinserti32x8', 'vinsertps',
  'vcmpps', 'vcmppd', 'vcmpss', 'vcmpsd',
  'vcomiss', 'vcomisd', 'vucomiss', 'vucomisd',
  'vcvtps2pd', 'vcvtpd2ps', 'vcvtps2dq', 'vcvtpd2dq',
  'vcvtdq2ps', 'vcvtdq2pd', 'vcvttpd2dq', 'vcvttps2dq',
  'vcvtss2sd', 'vcvtsd2ss', 'vcvtsi2ss', 'vcvtsi2sd',
  'vcvtss2si', 'vcvtsd2si', 'vcvttss2si', 'vcvttsd2si',
  'vhaddps', 'vhaddpd', 'vhsubps', 'vhsubpd',
  'vaddsubps', 'vaddsubpd',
  'vdpps', 'vdppd',
  'vpaddb', 'vpaddw', 'vpaddd', 'vpaddq',
  'vpsubb', 'vpsubw', 'vpsubd', 'vpsubq',
  'vpand', 'vpor', 'vpxor', 'vpandn',
  'vpmullw', 'vpmulld', 'vpmullq', 'vpmuldq', 'vpmuludq',
  'vpmulhw', 'vpmulhuw', 'vpmulhrsw',
  'vpminsb', 'vpminsw', 'vpminsd', 'vpminsq',
  'vpminub', 'vpminuw', 'vpminud', 'vpminuq',
  'vpmaxsb', 'vpmaxsw', 'vpmaxsd', 'vpmaxsq',
  'vpmaxub', 'vpmaxuw', 'vpmaxud', 'vpmaxuq',
  'vpsllw', 'vpslld', 'vpsllq', 'vpsllvw', 'vpsllvd', 'vpsllvq',
  'vpsrlw', 'vpsrld', 'vpsrlq', 'vpsrlvw', 'vpsrlvd', 'vpsrlvq',
  'vpsraw', 'vpsrad', 'vpsraq', 'vpsravw', 'vpsravd', 'vpsravq',
  'vpslldq', 'vpsrldq',
  'vpacksswb', 'vpackssdw', 'vpackuswb', 'vpackusdw',
  'vpunpcklbw', 'vpunpcklwd', 'vpunpckldq', 'vpunpcklqdq',
  'vpunpckhbw', 'vpunpckhwd', 'vpunpckhdq', 'vpunpckhqdq',
  'vunpcklps', 'vunpcklpd', 'vunpckhps', 'vunpckhpd',
  'vfmadd132ps', 'vfmadd132pd', 'vfmadd132ss', 'vfmadd132sd',
  'vfmadd213ps', 'vfmadd213pd', 'vfmadd213ss', 'vfmadd213sd',
  'vfmadd231ps', 'vfmadd231pd', 'vfmadd231ss', 'vfmadd231sd',
  'vfmsub132ps', 'vfmsub132pd', 'vfmsub132ss', 'vfmsub132sd',
  'vfmsub213ps', 'vfmsub213pd', 'vfmsub213ss', 'vfmsub213sd',
  'vfmsub231ps', 'vfmsub231pd', 'vfmsub231ss', 'vfmsub231sd',
  'vfnmadd132ps', 'vfnmadd132pd', 'vfnmadd132ss', 'vfnmadd132sd',
  'vfnmadd213ps', 'vfnmadd213pd', 'vfnmadd213ss', 'vfnmadd213sd',
  'vfnmadd231ps', 'vfnmadd231pd', 'vfnmadd231ss', 'vfnmadd231sd',
  'vfnmsub132ps', 'vfnmsub132pd', 'vfnmsub132ss', 'vfnmsub132sd',
  'vfnmsub213ps', 'vfnmsub213pd', 'vfnmsub213ss', 'vfnmsub213sd',
  'vfnmsub231ps', 'vfnmsub231pd', 'vfnmsub231ss', 'vfnmsub231sd',
  'vgatherdps', 'vgatherdpd', 'vgatherqps', 'vgatherqpd',
  'vpgatherdd', 'vpgatherdq', 'vpgatherqd', 'vpgatherqq',
  'vtestps', 'vtestpd', 'vzeroall', 'vzeroupper',
  'kmovb', 'kmovw', 'kmovd', 'kmovq',
  'kandw', 'kandb', 'kandd', 'kandq',
  'korw', 'korb', 'kord', 'korq',
  'kxorw', 'kxorb', 'kxord', 'kxorq',
  'knotw', 'knotb', 'knotd', 'knotq',
  'kaddw', 'kaddb', 'kaddd', 'kaddq',
  'ktestw', 'ktestb', 'ktestd', 'ktestq',
  'andn', 'bextr', 'blsi', 'blsmsk', 'blsr', 'bzhi',
  'mulx', 'pdep', 'pext', 'rorx', 'sarx', 'shlx', 'shrx',
  'aesdec', 'aesdeclast', 'aesenc', 'aesenclast', 'aesimc', 'aeskeygenassist',
  'sha1msg1', 'sha1msg2', 'sha1nexte', 'sha1rnds4',
  'sha256msg1', 'sha256msg2', 'sha256rnds2',
  'addsubpd', 'addsubps', 'haddpd', 'haddps', 'hsubpd', 'hsubps',
  'lddqu', 'movshdup', 'movsldup',
  'pabsb', 'pabsd', 'pabsw',
  'phaddd', 'phaddsw', 'phaddw', 'phsubd', 'phsubsw', 'phsubw',
  'pmaddubsw', 'pmulhrsw', 'pmulhrw',
  'pshufb', 'palignr',
  'psignb', 'psignd', 'psignw',
  'blendpd', 'blendps', 'blendvpd', 'blendvps', 'pblendvb', 'pblendw',
  'pminsb', 'pmaxsb', 'pminsd', 'pmaxsd', 'pminsw', 'pmaxsw',
  'pminub', 'pmaxub', 'pminud', 'pmaxud', 'pminuw', 'pmaxuw',
  'pmuldq', 'pmulld',
  'packusdw',
  'pcmpeqb', 'pcmpeqd', 'pcmpeqq', 'pcmpeqw',
  'pcmpgtb', 'pcmpgtd', 'pcmpgtq', 'pcmpgtw',
  'ptest',
  'pmovsxbd', 'pmovsxbq', 'pmovsxbw',
  'pmovzxbd', 'pmovzxbq', 'pmovzxbw',
  'pmulhuw', 'pmulhw', 'pmullw', 'pmuludq',
  'roundpd', 'roundps', 'roundsd', 'roundss',
  'dppd', 'dpps',
  'extractps', 'insertps',
  'pshufd', 'pshufhw', 'pshuflw', 'pshufw',
  'phminposuw', 'mpsadbw', 'movntdqa',
  'pcmpestri', 'pcmpestrm', 'pcmpistri', 'pcmpistrm',
  'vaesdec', 'vaesdeclast', 'vaesenc', 'vaesenclast', 'vaesimc', 'vaeskeygenassist',
  'valignd', 'valignq',
  'vblendmb', 'vblendmd', 'vblendmpd', 'vblendmps', 'vblendmq', 'vblendmw',
  'vbroadcastf32x8', 'vbroadcasti32x8',
  'vcompresspd', 'vcompressps',
  'vcvtpd2qq', 'vcvtpd2udq', 'vcvtpd2uqq', 'vcvtph2ps', 'vcvtps2ph', 'vcvtps2qq', 'vcvtps2udq', 'vcvtps2uqq',
  'vcvtqq2pd', 'vcvtqq2ps', 'vcvtsd2usi', 'vcvtss2usi',
  'vcvttpd2qq', 'vcvttpd2udq', 'vcvttpd2uqq', 'vcvttps2qq', 'vcvttps2udq', 'vcvttps2uqq',
  'vcvttsd2usi', 'vcvttss2usi', 'vcvtudq2pd', 'vcvtudq2ps', 'vcvtuqq2pd', 'vcvtuqq2ps',
  'vcvtusi2sd', 'vcvtusi2ss',
  'vdbpsadbw',
  'vexp2pd', 'vexp2ps', 'vexpandpd', 'vexpandps',
  'vextractf64x4', 'vextracti64x4',
  'vfixupimmpd', 'vfixupimmps', 'vfixupimmsd', 'vfixupimmss',
  'vfmaddpd', 'vfmaddps', 'vfmaddsd', 'vfmaddss',
  'vfmaddsub132pd', 'vfmaddsub132ps', 'vfmaddsub213pd', 'vfmaddsub213ps', 'vfmaddsub231pd', 'vfmaddsub231ps',
  'vfmaddsubpd', 'vfmaddsubps',
  'vfmsubadd132pd', 'vfmsubadd132ps', 'vfmsubadd213pd', 'vfmsubadd213ps', 'vfmsubadd231pd', 'vfmsubadd231ps',
  'vfmsubaddpd', 'vfmsubaddps', 'vfmsubpd', 'vfmsubps', 'vfmsubsd', 'vfmsubss',
  'vfnmaddpd', 'vfnmaddps', 'vfnmaddsd', 'vfnmaddss',
  'vfnmsubpd', 'vfnmsubps', 'vfnmsubsd', 'vfnmsubss',
  'vfpclasspd', 'vfpclassps', 'vfpclasssd', 'vfpclassss',
  'vfrczpd', 'vfrczps', 'vfrczsd', 'vfrczss',
  'vgatherpf0dpd', 'vgatherpf0dps', 'vgatherpf0qpd', 'vgatherpf0qps',
  'vgatherpf1dpd', 'vgatherpf1dps', 'vgatherpf1qpd', 'vgatherpf1qps',
  'vgetexppd', 'vgetexpps', 'vgetexpsd', 'vgetexpss',
  'vgetmantpd', 'vgetmantps', 'vgetmantsd', 'vgetmantss',
  'vinsertf64x4', 'vinserti64x4',
  'vlddqu', 'vldmxcsr',
  'vmaskmovdqu', 'vmaskmovpd', 'vmaskmovps',
  'vmovdqu16', 'vmovdqu8', 'vmovmskpd', 'vmovmskps',
  'vmovntdq', 'vmovntdqa', 'vmovntpd', 'vmovntps',
  'vmpsadbw',
  'vpabsb', 'vpabsd', 'vpabsq', 'vpabsw',
  'vpaddsb', 'vpaddsw', 'vpaddusb', 'vpaddusw',
  'vpalignr',
  'vpandd', 'vpandnd', 'vpandnq', 'vpandq',
  'vpavgb', 'vpavgw',
  'vpblendvb',
  'vpbroadcastb', 'vpbroadcastd', 'vpbroadcastmb2d', 'vpbroadcastmb2q', 'vpbroadcastq', 'vpbroadcastw',
  'vpclmulqdq', 'vpcmov',
  'vpcmpb', 'vpcmpd', 'vpcmpeqb', 'vpcmpeqd', 'vpcmpeqq', 'vpcmpeqw',
  'vpcmpestri', 'vpcmpestrm', 'vpcmpgtb', 'vpcmpgtd', 'vpcmpgtq', 'vpcmpgtw',
  'vpcmpistri', 'vpcmpistrm',
  'vpcmpq', 'vpcmpub', 'vpcmpud', 'vpcmpuq', 'vpcmpuw', 'vpcmpw',
  'vpcomb', 'vpcomd', 'vpcompressd', 'vpcompressq', 'vpcomq',
  'vpcomub', 'vpcomud', 'vpcomuq', 'vpcomuw', 'vpcomw',
  'vpconflictd', 'vpconflictq',
  'vpermil2pd', 'vpermil2ps', 'vpermt2pd', 'vpermt2ps',
  'vpexpandd', 'vpexpandq',
  'vpextrb', 'vpextrd', 'vpextrq', 'vpextrw',
  'vphaddbd', 'vphaddbq', 'vphaddbw', 'vphaddd', 'vphadddq', 'vphaddsw',
  'vphaddubd', 'vphaddubq', 'vphaddubw', 'vphaddudq', 'vphadduwd', 'vphadduwq',
  'vphaddw', 'vphaddwd', 'vphaddwq', 'vphminposuw',
  'vphsubbw', 'vphsubd', 'vphsubdq', 'vphsubsw', 'vphsubw', 'vphsubwd',
  'vpinsrb', 'vpinsrd', 'vpinsrq', 'vpinsrw',
  'vplzcntd', 'vplzcntq',
  'vpmacsdd', 'vpmacsdqh', 'vpmacsdql', 'vpmacssdd', 'vpmacssdqh', 'vpmacssdql',
  'vpmacsswd', 'vpmacssww', 'vpmacswd', 'vpmacsww',
  'vpmadcsswd', 'vpmadcswd',
  'vpmadd52huq', 'vpmadd52luq', 'vpmaddubsw', 'vpmaddwd',
  'vpmaskmovd', 'vpmaskmovq',
  'vpmovb2m', 'vpmovd2m', 'vpmovdb', 'vpmovdw',
  'vpmovm2b', 'vpmovm2d', 'vpmovm2q', 'vpmovm2w',
  'vpmovmskb', 'vpmovq2m', 'vpmovqb', 'vpmovqd', 'vpmovqw',
  'vpmovsdb', 'vpmovsdw', 'vpmovsqb', 'vpmovsqd', 'vpmovsqw', 'vpmovswb',
  'vpmovsxbd', 'vpmovsxbq', 'vpmovsxbw', 'vpmovsxdq', 'vpmovsxwd', 'vpmovsxwq',
  'vpmovusdb', 'vpmovusdw', 'vpmovusqb', 'vpmovusqd', 'vpmovusqw', 'vpmovuswb',
  'vpmovw2m', 'vpmovwb',
  'vpmovzxbd', 'vpmovzxbq', 'vpmovzxbw', 'vpmovzxdq', 'vpmovzxwd', 'vpmovzxwq',
  'vpmultishiftqb',
  'vpord', 'vporq', 'vpperm',
  'vprold', 'vprolq', 'vprolvd', 'vprolvq',
  'vprord', 'vprorq', 'vprorvd', 'vprorvq',
  'vprotb', 'vprotd', 'vprotq', 'vprotw',
  'vpsadbw',
  'vpscatterdd', 'vpscatterdq', 'vpscatterqd', 'vpscatterqq',
  'vpshab', 'vpshad', 'vpshaq', 'vpshaw',
  'vpshlb', 'vpshld', 'vpshlq', 'vpshlw',
  'vpshufb', 'vpshufd', 'vpshufhw', 'vpshuflw',
  'vpsignb', 'vpsignd', 'vpsignw',
  'vpsubsb', 'vpsubsw', 'vpsubusb', 'vpsubusw',
  'vpternlogd', 'vpternlogq',
  'vptest',
  'vptestmb', 'vptestmd', 'vptestmq', 'vptestmw',
  'vptestnmb', 'vptestnmd', 'vptestnmq', 'vptestnmw',
  'vpxord', 'vpxorq',
  'vrangepd', 'vrangeps', 'vrangesd', 'vrangess',
  'vrcp14pd', 'vrcp14ps', 'vrcp14sd', 'vrcp14ss',
  'vrcp28pd', 'vrcp28ps', 'vrcp28sd', 'vrcp28ss',
  'vreducepd', 'vreduceps', 'vreducesd', 'vreducess',
  'vrndscalepd', 'vrndscaleps', 'vrndscalesd', 'vrndscaless',
  'vrsqrt14pd', 'vrsqrt14ps', 'vrsqrt14sd', 'vrsqrt14ss',
  'vrsqrt28pd', 'vrsqrt28ps', 'vrsqrt28sd', 'vrsqrt28ss',
  'vscalefpd', 'vscalefps', 'vscalefsd', 'vscalefss',
  'vscatterdpd', 'vscatterdps',
  'vscatterpf0dpd', 'vscatterpf0dps', 'vscatterpf0qpd', 'vscatterpf0qps',
  'vscatterpf1dpd', 'vscatterpf1dps', 'vscatterpf1qpd', 'vscatterpf1qps',
  'vscatterqpd', 'vscatterqps',
  'vstmxcsr',
  'f2xm1', 'fabs', 'fadd', 'faddp', 'fbld', 'fbstp', 'fchs', 'fclex',
  'fcmovb', 'fcmovbe', 'fcmove', 'fcmovnb', 'fcmovnbe', 'fcmovne', 'fcmovnu', 'fcmovu',
  'fcom', 'fcomi', 'fcomip', 'fcomp', 'fcompp', 'fcos', 'fdecstp',
  'fdiv', 'fdivp', 'fdivr', 'fdivrp', 'femms', 'ffree',
  'fiadd', 'ficom', 'ficomp', 'fidiv', 'fidivr', 'fild', 'fimul',
  'fincstp', 'finit', 'fist', 'fistp', 'fisttp', 'fisub', 'fisubr',
  'fld', 'fld1', 'fldcw', 'fldenv', 'fldl2e', 'fldl2t', 'fldlg2', 'fldln2', 'fldpi', 'fldz',
  'fmul', 'fmulp', 'fnclex', 'fninit', 'fnop', 'fnsave', 'fnstcw', 'fnstenv', 'fnstsw',
  'fpatan', 'fprem', 'fprem1', 'fptan', 'frndint', 'frstor', 'fsave', 'fscale',
  'fsin', 'fsincos', 'fsqrt', 'fst', 'fstcw', 'fstenv', 'fstp', 'fstsw',
  'fsub', 'fsubp', 'fsubr', 'fsubrp', 'ftst',
  'fucom', 'fucomi', 'fucomip', 'fucomp', 'fucompp',
  'fwait', 'fxam', 'fxch', 'fxrstor', 'fxrstor64', 'fxsave', 'fxsave64',
  'fxtract', 'fyl2x', 'fyl2xp1'
];

const EMPTY_OPERAND = '{ .kind = 0, .size = 0, .fixed = NULL }';

const gprNameMap = new Map();
function addGprName(name, size, encoding) {
  gprNameMap.set(name, { class: 'gpr', size, encoding });
}

for (const reg of registers) {
  addGprName(reg.r64, 64, reg.encoding);
  addGprName(reg.r32, 32, reg.encoding);
  addGprName(reg.r16, 16, reg.encoding);
  addGprName(reg.r8, 8, reg.encoding);
  for (const alias of reg.aliases) {
    addGprName(alias, 64, reg.encoding);
  }
}

const registerClassDefs = [
  { name: 'mm', prefix: 'mm', max: 8, size: 64 },
  { name: 'xmm', prefix: 'xmm', max: 32, size: 128 },
  { name: 'ymm', prefix: 'ymm', max: 32, size: 256 },
  { name: 'zmm', prefix: 'zmm', max: 32, size: 512 },
  { name: 'k', prefix: 'k', max: 8, size: 64 }
];

const registerClassCheckFuncs = {
  mm: 'is_mmx_reg',
  xmm: 'is_xmm_reg',
  ymm: 'is_ymm_reg',
  zmm: 'is_zmm_reg',
  k: 'is_mask_reg'
};

const vexMmMap = { '': 0, '0F': 0b01, '0F38': 0b10, '0F3A': 0b11 };
const vexPpMap = { '': 0, '66': 0b01, 'F3': 0b10, 'F2': 0b11 };

function vexLBit(tag) {
  const value = (tag || '').toUpperCase();
  if (value === '256' || value === 'L1') return 1;
  return 0;
}

function vexWBit(tag) {
  const value = (tag || '').toUpperCase();
  return value === 'W1' ? 1 : 0;
}

const evexMmMap = vexMmMap;
const evexPpMap = vexPpMap;

function evexLLBits(tag) {
  const value = (tag || '').toUpperCase();
  if (value === '512' || value === 'L2') return 0b10;
  if (value === '256' || value === 'L1') return 0b01;
  if (value === '128' || value === 'L0' || value === 'LZ') return 0b00;
  return 0b00;
}

function evexWBit(tag) {
  const value = (tag || '').toUpperCase();
  return value === 'W1' ? 1 : 0;
}

function resolveRegisterInfo(name) {
  if (!name) return null;
  const lower = name.toLowerCase();
  if (gprNameMap.has(lower)) {
    const info = gprNameMap.get(lower);
    return { class: info.class, size: info.size, encoding: info.encoding };
  }
  for (const cls of registerClassDefs) {
    if (!lower.startsWith(cls.prefix)) continue;
    const suffix = lower.slice(cls.prefix.length);
    if (!suffix.length || !/^\d+$/.test(suffix)) continue;
    const index = parseInt(suffix, 10);
    if (Number.isNaN(index) || index < 0 || index >= cls.max) continue;
    return { class: cls.name, size: cls.size, encoding: index };
  }
  return null;
}

function collectInstructionEntries(mnemonics) {
  const whitelist = new Set(mnemonics);
  const entries = [];

  for (const [mnemonic, variants] of Object.entries(x86.map)) {
    if (!whitelist.has(mnemonic)) continue;

    const groups = new Map();

    for (const asmVariant of variants) {
      const parsed = parseVariant(mnemonic, asmVariant);
      if (!parsed) continue;

      const signature = buildOperandSignature(parsed.operands);
      const key = `${mnemonic}|${signature}`;
      if (!groups.has(key)) {
        groups.set(key, {
          mnemonic,
          signature,
          operands: parsed.operands,
          variants: []
        });
      }
      groups.get(key).variants.push(parsed);
    }

    for (const value of groups.values()) entries.push(value);
  }

  return entries;
}

if (process.env.DUMP_X86_ENTRIES) {
  const entries = collectInstructionEntries(SUPPORTED_MNEMONICS);
  const target = process.env.DUMP_MNEMONIC;
  const filtered = target ? entries.filter(entry => entry.mnemonic === target) : entries;
  console.log(JSON.stringify(filtered, null, 2));
  process.exit(0);
}

const instructionEntries = collectInstructionEntries(SUPPORTED_MNEMONICS);
const entriesByMnemonic = new Map();
for (const entry of instructionEntries) {
  if (!entriesByMnemonic.has(entry.mnemonic)) {
    entriesByMnemonic.set(entry.mnemonic, []);
  }
  entriesByMnemonic.get(entry.mnemonic).push(entry);
}
const generatedMnemonics = new Set();

function functionNameForMnemonic(mnemonic) {
  return labelAwareMnemonics.has(mnemonic) ? `cj_${mnemonic}_impl` : `cj_${mnemonic}`;
}

function immediateMaxLiteral(size) {
  switch (size) {
    case 8: return '0xFF';
    case 16: return '0xFFFF';
    case 32: return '0xFFFFFFFFu';
    case 64: return 'UINT64_C(0xFFFFFFFFFFFFFFFF)';
    default: return null;
  }
}

function signedRange(size) {
  switch (size) {
    case 8: return { min: '-128', max: '127' };
    case 16: return { min: '-32768', max: '32767' };
    case 32: return { min: '-2147483648LL', max: '2147483647LL' };
    case 64: return { min: '-9223372036854775808LL', max: '9223372036854775807LL' };
    default: return null;
  }
}

function cartesianProduct(arrays) {
  if (!arrays.length) return [[]];
  const [first, ...rest] = arrays;
  const tailProduct = cartesianProduct(rest);
  const result = [];
  for (const item of first) {
    for (const tail of tailProduct) {
      result.push([item, ...tail]);
    }
  }
  return result;
}

function buildOperandCases(spec, paramName, operandIndex, variant) {
  if (!spec) return [];

  const cases = [];
  const size = spec.size || 0;
  const addRegisterCase = ({ fixed, label, regClass }) => {
    const guardParts = [`${paramName}.type == CJ_REGISTER`];
    if (fixed) {
      guardParts.push(`${paramName}.reg && strcmp(${paramName}.reg, "${fixed}") == 0`);
    } else if (size) {
      guardParts.push(`detect_reg_size(${paramName}.reg) == ${size}`);
      const classCheck = regClass && registerClassCheckFuncs[regClass];
      if (classCheck) guardParts.push(`${classCheck}(${paramName}.reg)`);
    } else if (regClass && registerClassCheckFuncs[regClass]) {
      guardParts.push(`${registerClassCheckFuncs[regClass]}(${paramName}.reg)`);
    }
    const registerVar = `${paramName}_reg`;
    const setup = [
      `int8_t ${registerVar} = parse_reg(${paramName}.reg);`,
      `if (${registerVar} < 0) return;`
    ];
    return {
      param: paramName,
      operandIndex,
      kind: 'register',
      size,
      fixed: fixed || null,
      regClass: regClass || spec.regClass || null,
      guardParts,
      setup,
      postChecks: [],
      registerVar,
      label
    };
  };

  switch (spec.kind) {
    case 'reg':
      cases.push(addRegisterCase({ fixed: spec.fixed || null, regClass: spec.regClass || null }));
      break;
    case 'rm':
      cases.push(addRegisterCase({ regClass: spec.regClass || null }));
      cases.push({
        param: paramName,
        operandIndex,
        kind: 'memory',
        size,
        guardParts: [`${paramName}.type == CJ_MEMORY`],
        setup: [
          `int8_t ${paramName}_base_reg = ${paramName}.mem.base ? parse_reg(${paramName}.mem.base) : -1;`,
          `int8_t ${paramName}_index_reg = ${paramName}.mem.index ? parse_reg(${paramName}.mem.index) : -1;`,
          `uint8_t ${paramName}_rex_b = (${paramName}_base_reg >= 8) ? 1 : 0;`,
          `uint8_t ${paramName}_rex_x = (${paramName}_index_reg >= 8) ? 1 : 0;`
        ],
        postChecks: [],
        baseRegVar: `${paramName}_base_reg`,
        indexRegVar: `${paramName}_index_reg`,
        rexBVar: `${paramName}_rex_b`,
        rexXVar: `${paramName}_rex_x`
      });
      break;
    case 'mem':
      cases.push({
        param: paramName,
        operandIndex,
        kind: 'memory',
        size,
        guardParts: [`${paramName}.type == CJ_MEMORY`],
        setup: [
          `int8_t ${paramName}_base_reg = ${paramName}.mem.base ? parse_reg(${paramName}.mem.base) : -1;`,
          `int8_t ${paramName}_index_reg = ${paramName}.mem.index ? parse_reg(${paramName}.mem.index) : -1;`,
          `uint8_t ${paramName}_rex_b = (${paramName}_base_reg >= 8) ? 1 : 0;`,
          `uint8_t ${paramName}_rex_x = (${paramName}_index_reg >= 8) ? 1 : 0;`
        ],
        postChecks: [],
        baseRegVar: `${paramName}_base_reg`,
        indexRegVar: `${paramName}_index_reg`,
        rexBVar: `${paramName}_rex_b`,
        rexXVar: `${paramName}_rex_x`
      });
      break;
    case 'segment':
      cases.push({
        param: paramName,
        operandIndex,
        kind: 'segment',
        size,
        guardParts: [`${paramName}.type == CJ_REGISTER`, `${paramName}.reg && strcmp(${paramName}.reg, "${spec.fixed}") == 0`],
        setup: [],
        postChecks: [],
        fixed: spec.fixed
      });
      break;
    case 'imm': {
      const guardParts = [`${paramName}.type == CJ_CONSTANT`];
      const operandSize = variant?.encoding?.operandSize || 0;
      const immSize = variant?.encoding?.immSize || size;

      // If immediate is smaller than operand size, it's sign-extended
      const isSignExtended = immSize < operandSize;

      if (isSignExtended) {
        // Use signed range checking (like 'rel' operands)
        const range = signedRange(size);
        const immVar = `${paramName}_imm`;
        const setup = [`int64_t ${immVar} = (int64_t)${paramName}.constant;`];
        const postChecks = range ? [`if (${immVar} < ${range.min} || ${immVar} > ${range.max}) return;`] : [];
        cases.push({
          param: paramName,
          operandIndex,
          kind: 'imm',
          size,
          guardParts,
          setup,
          postChecks,
          valueExpr: immVar
        });
      } else {
        // Use unsigned range checking (original behavior)
        const maxLiteral = immediateMaxLiteral(size);
        if (maxLiteral) {
          guardParts.push(`${paramName}.constant <= ${maxLiteral}`);
        }
        cases.push({
          param: paramName,
          operandIndex,
          kind: 'imm',
          size,
          guardParts,
          setup: [],
          postChecks: [],
          valueExpr: `${paramName}.constant`
        });
      }
      break;
    }
    case 'rel': {
      const range = signedRange(size);
      const guardParts = [`${paramName}.type == CJ_CONSTANT`];
      const relVar = `${paramName}_rel`;
      const setup = [`int64_t ${relVar} = (int64_t)${paramName}.constant;`];
      const postChecks = range ? [`if (${relVar} < ${range.min} || ${relVar} > ${range.max}) return;`] : [];
      cases.push({
        param: paramName,
        operandIndex,
        kind: 'rel',
        size,
        guardParts,
        setup,
        postChecks,
        valueExpr: relVar
      });
      break;
    }
    case 'const':
      cases.push({
        param: paramName,
        operandIndex,
        kind: 'const',
        size,
        value: spec.value,
        guardParts: [`${paramName}.type == CJ_CONSTANT`, `${paramName}.constant == ${spec.value}`],
        setup: [],
        postChecks: [],
        valueExpr: `${paramName}.constant`
      });
      break;
    default:
      return [];
  }

  return cases;
}

function getParamSpec(entry, variant, paramIndex, paramCount) {
  if (paramIndex < entry.operands.length) {
    return entry.operands[paramIndex];
  }
  const implicit = variant.implicitOperands || [];
  if (paramIndex < entry.operands.length + implicit.length) {
    return implicit[paramIndex - entry.operands.length];
  }
  return null;
}

function joinConditions(parts) {
  if (!parts.length) return '1';
  return parts.join(' && ');
}

function joinBitExpr(exprs) {
  if (!exprs.length) return '0';
  if (exprs.length === 1) return exprs[0];
  return `((${exprs.join(') | (')}))`;
}

function joinOrExpr(exprs) {
  if (!exprs.length) return '0';
  if (exprs.length === 1) return exprs[0];
  return `((${exprs.join(') || (')}))`;
}

function emitImmediateLines(indent, variant, valueExpr, kind) {
  const size = variant.encoding.immSize;
  if (!size) return [];

  const lines = [];
  const uintType = size === 8 ? 'uint8_t'
    : size === 16 ? 'uint16_t'
    : size === 32 ? 'uint32_t'
    : 'uint64_t';
  const func = `cj_add_u${size}`;
  if (kind === 'rel') {
    const intType = size === 8 ? 'int8_t'
      : size === 16 ? 'int16_t'
      : size === 32 ? 'int32_t'
      : 'int64_t';
    lines.push(`${indent}${func}(ctx, (${uintType})(${intType})${valueExpr});`);
  } else {
    lines.push(`${indent}${func}(ctx, (${uintType})${valueExpr});`);
  }
  return lines;
}

function generateEmitterFromEntries(mnemonic, paramNames) {
  const entries = entriesByMnemonic.get(mnemonic) || [];
  if (!entries.length) return false;

  const funcName = functionNameForMnemonic(mnemonic);
  console.log(`void ${funcName}(cj_ctx* ctx${paramNames.length ? ', ' : ''}${paramNames.map(name => `cj_operand ${name}`).join(', ')}) {`);

  let emittedAnyVariant = false;

  const sortedEntries = [...entries].sort((a, b) => a.signature.localeCompare(b.signature));

  for (const entry of sortedEntries) {
    if (entry.operands.length > paramNames.length) continue;
    for (const variant of entry.variants) {
      const paramSpecs = paramNames.map((name, idx) => getParamSpec(entry, variant, idx, paramNames.length));
      if (paramSpecs.some(spec => !spec)) continue;

      const caseOptions = paramSpecs.map((spec, idx) => buildOperandCases(spec, paramNames[idx], idx < entry.operands.length ? idx : -1, variant));
      if (caseOptions.some(options => options.length === 0)) continue;

      const combinations = cartesianProduct(caseOptions);

      for (const combo of combinations) {
        emittedAnyVariant = true;
        const guardParts = combo.flatMap(c => c.guardParts);
        const condition = joinConditions(guardParts);

        console.log(`  if (${condition}) {`);

        const operandCaseMap = new Map();
        combo.forEach((c, idx) => {
          if (c.operandIndex >= 0) {
            operandCaseMap.set(c.operandIndex, c);
          }
        });

        for (const c of combo) {
          for (const line of c.setup) {
            console.log(`    ${line}`);
          }
        }
        for (const c of combo) {
          for (const check of c.postChecks) {
            console.log(`    ${check}`);
          }
        }

        for (const prefix of variant.encoding.prefixes || []) {
          console.log(`    cj_add_u8(ctx, ${hexByte(prefix)});`);
        }

        const metadata = variant.encoding.metadata || {};
        const isEvex = !!variant.encoding.evex;
        const isVex = !!variant.encoding.vex && !isEvex;

        if (isVex) {
          const vexInfo = variant.encoding.vex;
          const mmBits = vexMmMap[vexInfo.mm || ''] ?? 0;
          const ppBits = vexPpMap[vexInfo.pp || ''] ?? 0;
          const lBit = vexLBit(vexInfo.l || '');
          const wBit = vexWBit(vexInfo.w || '');

          const regCase = metadata.modrmRegOperand >= 0 ? operandCaseMap.get(metadata.modrmRegOperand) : null;
          const rmCase = metadata.modrmRmOperand >= 0 ? operandCaseMap.get(metadata.modrmRmOperand) : null;
          const vexMeta = metadata.vex || {};
          const vCase = vexMeta.vvvvOperand >= 0 ? operandCaseMap.get(vexMeta.vvvvOperand) : null;

          const rExpr = regCase && regCase.kind === 'register' ? `(uint8_t)((${regCase.registerVar} >> 3) & 1)` : '0';
          const xExpr = rmCase && rmCase.kind === 'memory' ? (rmCase.rexXVar || '0') : '0';
          const bExpr = rmCase && rmCase.kind === 'register'
            ? `(uint8_t)((${rmCase.registerVar} >> 3) & 1)`
            : (rmCase && rmCase.kind === 'memory' ? (rmCase.rexBVar || '0') : '0');
          const vExpr = vCase && vCase.kind === 'register' ? `(${vCase.registerVar} & 15)` : '0xF';

          console.log(`    uint8_t vex_r = ${rExpr};`);
          console.log(`    uint8_t vex_x = ${xExpr};`);
          console.log(`    uint8_t vex_b = ${bExpr};`);
          console.log(`    uint8_t vex_v = ${vExpr};`);
          console.log(`    uint8_t vex_r_inv = (uint8_t)(vex_r ^ 1);`);
          console.log(`    uint8_t vex_x_inv = (uint8_t)(vex_x ^ 1);`);
          console.log(`    uint8_t vex_b_inv = (uint8_t)(vex_b ^ 1);`);
          console.log(`    uint8_t vex_v_inv = (uint8_t)((vex_v ^ 0xF) & 0xF);`);
          console.log(`    cj_add_u8(ctx, 0xC4);`);
          console.log(`    cj_add_u8(ctx, (uint8_t)((vex_r_inv << 7) | (vex_x_inv << 6) | (vex_b_inv << 5) | ${mmBits}));`);
          console.log(`    cj_add_u8(ctx, (uint8_t)((${wBit} << 7) | (vex_v_inv << 3) | (${lBit} << 2) | ${ppBits}));`);
        } else if (isEvex) {
          const evexInfo = variant.encoding.evex;
          const mmBits = evexMmMap[evexInfo.mm || ''] ?? 0;
          const ppBits = evexPpMap[evexInfo.pp || ''] ?? 0;
          const llBits = evexLLBits(evexInfo.l || '');
          const wBit = evexWBit(evexInfo.w || '');

          const regCase = metadata.modrmRegOperand >= 0 ? operandCaseMap.get(metadata.modrmRegOperand) : null;
          const rmCase = metadata.modrmRmOperand >= 0 ? operandCaseMap.get(metadata.modrmRmOperand) : null;
          const evexMeta = metadata.evex || {};
          const vCase = evexMeta.vvvvOperand >= 0 ? operandCaseMap.get(evexMeta.vvvvOperand) : null;




          const rExpr = regCase && regCase.kind === 'register' ? `(uint8_t)((${regCase.registerVar} >> 3) & 1)` : '0';
          const rPrimeExpr = regCase && regCase.kind === 'register' ? `(uint8_t)((${regCase.registerVar} >> 4) & 1)` : '0';

          const xExpr = rmCase && rmCase.kind === 'memory' ? (rmCase.rexXVar || '0') : '0';
          const bExpr = rmCase && rmCase.kind === 'register'
            ? `(uint8_t)((${rmCase.registerVar} >> 3) & 1)`
            : (rmCase && rmCase.kind === 'memory' ? (rmCase.rexBVar || '0') : '0');

          const vExpr = vCase && vCase.kind === 'register' ? `(${vCase.registerVar} & 15)` : '0xF';
          const vPrimeExpr = vCase && vCase.kind === 'register' ? `(uint8_t)((${vCase.registerVar} >> 4) & 1)` : '0';

          console.log(`    uint8_t evex_r = ${rExpr};`);
          console.log(`    uint8_t evex_x = ${xExpr};`);
          console.log(`    uint8_t evex_b = ${bExpr};`);
          console.log(`    uint8_t evex_r_prime = ${rPrimeExpr};`);
          console.log(`    uint8_t evex_v = ${vExpr};`);
          console.log(`    uint8_t evex_v_prime = ${vPrimeExpr};`);


          console.log(`    uint8_t evex_r_inv = (uint8_t)(evex_r ^ 1);`);
          console.log(`    uint8_t evex_x_inv = (uint8_t)(evex_x ^ 1);`);
          console.log(`    uint8_t evex_b_inv = (uint8_t)(evex_b ^ 1);`);
          console.log(`    uint8_t evex_r_prime_inv = (uint8_t)(evex_r_prime ^ 1);`);
          console.log(`    uint8_t evex_v_inv = (uint8_t)((evex_v ^ 0xF) & 0xF);`);
          console.log(`    uint8_t evex_v_prime_inv = (uint8_t)(evex_v_prime ^ 1);`);


          console.log(`    cj_add_u8(ctx, 0x62);`);


          console.log(`    cj_add_u8(ctx, (uint8_t)((evex_r_inv << 7) | (evex_x_inv << 6) | (evex_b_inv << 5) | (evex_r_prime_inv << 4) | ${mmBits}));`);


          console.log(`    cj_add_u8(ctx, (uint8_t)((${wBit} << 7) | (evex_v_inv << 3) | (1 << 2) | ${ppBits}));`);



          const zBit = 0;
          const bBit = 0;
          const aaaBits = 0;
          console.log(`    cj_add_u8(ctx, (uint8_t)((${zBit} << 7) | (${llBits} << 5) | (${bBit} << 4) | (evex_v_prime_inv << 3) | ${aaaBits}));`);
        } else {
          const rexRExprs = [];
          const rexBExprs = [];
          const rexXExprs = [];
          const rexLowExprs = [];

          if (metadata.modrmRegOperand >= 0) {
            const regCase = operandCaseMap.get(metadata.modrmRegOperand);
            if (regCase && regCase.kind === 'register') {
              rexRExprs.push(`(${regCase.registerVar} >= 8) ? 1 : 0`);
              if (regCase.size === 8) rexLowExprs.push(`(${regCase.registerVar} >= 4)`);
            }
          }

          if (metadata.modrmRmOperand >= 0) {
            const rmCase = operandCaseMap.get(metadata.modrmRmOperand);
            if (rmCase) {
              if (rmCase.kind === 'register') {
                rexBExprs.push(`(${rmCase.registerVar} >= 8) ? 1 : 0`);
                if (rmCase.size === 8) rexLowExprs.push(`(${rmCase.registerVar} >= 4)`);
              } else if (rmCase.kind === 'memory') {
                rexBExprs.push(rmCase.rexBVar);
                rexXExprs.push(rmCase.rexXVar);
              }
            }
          }

          if (variant.encoding.opcodeReg && metadata.opcodeRegisterOperand >= 0) {
            const opRegCase = operandCaseMap.get(metadata.opcodeRegisterOperand);
            if (opRegCase && opRegCase.kind === 'register') {
              rexBExprs.push(`(${opRegCase.registerVar} >= 8) ? 1 : 0`);
              if (opRegCase.size === 8) rexLowExprs.push(`(${opRegCase.registerVar} >= 4)`);
            }
          }

          const rexW = variant.encoding.rexW ? 1 : 0;
          const rexRExpr = joinBitExpr(rexRExprs);
          const rexXExpr = joinBitExpr(rexXExprs);
          const rexBExpr = joinBitExpr(rexBExprs);
          const rexLowExpr = joinOrExpr(rexLowExprs);

          if (rexW || rexRExpr !== '0' || rexXExpr !== '0' || rexBExpr !== '0' || rexLowExpr !== '0') {
            console.log(`    uint8_t rex_w = ${rexW};`);
            console.log(`    uint8_t rex_r = ${rexRExpr};`);
            console.log(`    uint8_t rex_x = ${rexXExpr};`);
            console.log(`    uint8_t rex_b = ${rexBExpr};`);
            console.log(`    uint8_t need_rex = rex_w || rex_r || rex_x || rex_b;`);
            if (rexLowExpr !== '0') {
              console.log(`    if (!need_rex && ${rexLowExpr}) need_rex = 1;`);
            }
            console.log(`    if (need_rex) emit_rex(ctx, rex_w, rex_r, rex_x, rex_b);`);
          }
        }

        let opcodeExpression = null;
        if (variant.encoding.opcodeReg && metadata.opcodeRegisterOperand >= 0) {
          const opcodeCase = operandCaseMap.get(metadata.opcodeRegisterOperand);
          if (opcodeCase && opcodeCase.kind === 'register') {
            const opcodeBytes = variant.encoding.opcodeBytes.length
              ? variant.encoding.opcodeBytes
              : [variant.encoding.opcode];
            const lastByte = opcodeBytes[opcodeBytes.length - 1];
            opcodeExpression = `${hexByte(lastByte)} + (${opcodeCase.registerVar} & 7)`;
          }
        }

        emitOpcode('    ', variant.encoding, opcodeExpression);

        if (metadata.modrmType) {
          const regField = (() => {
            if (metadata.modrmType === 2) {
              return `${metadata.modrmRegConst}`;
            }
            if (metadata.modrmRegOperand >= 0) {
              const regCase = operandCaseMap.get(metadata.modrmRegOperand);
              if (regCase && regCase.kind === 'register') {
                return `${regCase.registerVar} & 7`;
              }
            }
            return '0';
          })();

          const rmCase = metadata.modrmRmOperand >= 0 ? operandCaseMap.get(metadata.modrmRmOperand) : null;
          if (rmCase && rmCase.kind === 'memory') {
            console.log(`    int mod = emit_memory_modrm(ctx, ${regField}, ${rmCase.param}.mem.base, ${rmCase.param}.mem.index, ${rmCase.param}.mem.scale, ${rmCase.param}.mem.disp);`);
            console.log(`    if (mod == 1) cj_add_u8(ctx, (int8_t)${rmCase.param}.mem.disp);`);
            console.log(`    else if (mod == 2) cj_add_u32(ctx, (uint32_t)${rmCase.param}.mem.disp);`);
          } else {
            const rmField = rmCase && rmCase.kind === 'register' ? `${rmCase.registerVar} & 7` : '0';
            console.log(`    emit_modrm(ctx, ${rmCase && rmCase.kind === 'register' ? '3' : '0'}, ${regField}, ${rmField});`);
          }
        }

        if (metadata.immediateOperand >= 0) {
          const immCase = operandCaseMap.get(metadata.immediateOperand) || combo[metadata.immediateOperand];
          if (immCase) {
            const kind = immCase.kind === 'rel' ? 'rel' : 'imm';
            const immLines = emitImmediateLines('    ', variant, immCase.valueExpr, kind);
            immLines.forEach(line => console.log(line));
          }
        }

        console.log(`    return;`);
        console.log(`  }`);
      }
    }
  }

  if (!emittedAnyVariant) {
    for (const name of paramNames) {
      console.log(`  (void)${name};`);
    }
    console.log(`  (void)ctx;`);
    console.log(`}`);
    console.log();
    return true;
  }

  console.log(`  (void)ctx;`);
  for (const name of paramNames) {
    console.log(`  (void)${name};`);
  }
  console.log(`}`);
  console.log();
  return true;
}

function findRelativeVariant(mnemonic) {
  const entries = entriesByMnemonic.get(mnemonic) || [];
  let best = null;

  for (const entry of entries) {
    for (const variant of entry.variants) {
      const relOperand = variant.operands.find(op => op.kind === 'rel');
      if (!relOperand || !variant.encoding) continue;

      const prefixes = variant.encoding.prefixes || [];
      const opcodeBytes = (variant.encoding.opcodeBytes && variant.encoding.opcodeBytes.length)
        ? variant.encoding.opcodeBytes
        : (typeof variant.encoding.opcode === 'number' ? [variant.encoding.opcode] : []);
      if (!opcodeBytes.length) continue;
      const bytes = [...prefixes, ...opcodeBytes];
      const size = relOperand.size;
      if (!size) continue;

      if (!best || size > best.size) {
        best = { bytes, size };
      }
    }
  }

  return best;
}

function generateLabelWrappers(mnemonics) {
  const wrappers = [];
  for (const name of mnemonics) {
    if (!labelAwareMnemonics.has(name)) continue;
    const variant = findRelativeVariant(name);
    if (!variant) continue;
    wrappers.push({ name, variant });
  }

  if (!wrappers.length) return;

  console.log('');
  for (const { name, variant } of wrappers) {
    const baseName = `cj_${name}`;
    const implName = functionNameForMnemonic(name);
    const labelFunc = `${baseName}_label`;
    const adapterName = `${baseName}_operand_adapter`;
    const widthBytes = variant.size / 8;
    const byteList = variant.bytes.map(hexByte).join(', ');

    console.log(`static inline void ${labelFunc}(cj_ctx* ctx, cj_label label) {`);
    console.log(`  const uint8_t opcode[] = { ${byteList} };`);
    console.log(`  cj_emit_x86_rel(ctx, opcode, sizeof(opcode), ${widthBytes}, label);`);
    console.log(`}`);
    console.log('');
    console.log(`static inline void ${adapterName}(cj_ctx* ctx, cj_operand target) {`);
    console.log(`  ${implName}(ctx, target);`);
    console.log(`}`);
    console.log('');
    console.log(`#define ${baseName}(ctx, target) \\`);
    console.log(`  _Generic((target), \\`);
    console.log(`      cj_label: ${labelFunc}, \\`);
    console.log(`      default: ${adapterName})(ctx, target)`);
    console.log('');
  }
}

function parseVariant(mnemonic, variant) {
  const operands = [];
  const implicitOperands = [];
  const allOperands = [];

  for (const operand of variant.operands) {
    const parsed = parseOperand(operand);
    if (!parsed) return null;
    allOperands.push(parsed);
    if (parsed.implicit) implicitOperands.push(parsed);
    else operands.push(parsed);
  }

  const encoding = parseEncoding(variant);
  if (!encoding) return null;

  annotateEncoding(operands, encoding);

  const opcodeString = variant.opcodeString || variant.opcode || '';
  return { mnemonic, operands, implicitOperands, allOperands, encoding, opcodeString };
}

function parseOperand(op) {
  const data = (op.data || '').toLowerCase();
  const result = { raw: op.data, implicit: !!op.implicit };

  if (!data) return null;

  if (data === '1') return { ...result, kind: 'const', value: 1 };
  if (data === 'cl') return { ...result, kind: 'reg', size: 8, fixed: 'cl', regClass: 'gpr' };
  if (data === 'al') return { ...result, kind: 'reg', size: 8, fixed: 'al', regClass: 'gpr' };
  if (data === 'ax') return { ...result, kind: 'reg', size: 16, fixed: 'ax', regClass: 'gpr' };
  if (data === 'eax') return { ...result, kind: 'reg', size: 32, fixed: 'eax', regClass: 'gpr' };
  if (data === 'rax') return { ...result, kind: 'reg', size: 64, fixed: 'rax', regClass: 'gpr' };
  if (data === 'dx') return { ...result, kind: 'reg', size: 16, fixed: 'dx', regClass: 'gpr' };
  if (data === 'edx') return { ...result, kind: 'reg', size: 32, fixed: 'edx', regClass: 'gpr' };
  if (data === 'rdx') return { ...result, kind: 'reg', size: 64, fixed: 'rdx', regClass: 'gpr' };
  if (['cs', 'ds', 'es', 'ss', 'fs', 'gs'].includes(data)) {
    return { ...result, kind: 'segment', fixed: data };
  }

  const vectorOnly = data.match(/^(xmm|ymm|zmm|mm|k)$/);
  if (vectorOnly) {
    const cls = vectorOnly[1];
    const def = registerClassDefs.find(entry => entry.name === cls);
    if (def) return { ...result, kind: 'reg', size: def.size, regClass: cls };
  }

  if (data.startsWith('imm')) {
    const size = parseInt(data.slice(3), 10);
    return { ...result, kind: 'imm', size };
  }
  if (data === 'ib') return { ...result, kind: 'imm', size: 8 };
  if (data === 'iw') return { ...result, kind: 'imm', size: 16 };
  if (data === 'id') return { ...result, kind: 'imm', size: 32 };
  if (data === 'iq') return { ...result, kind: 'imm', size: 64 };

  if (data.startsWith('rel')) {
    const size = parseInt(data.slice(3), 10);
    return { ...result, kind: 'rel', size };
  }

  if (data === 'st') return { ...result, kind: 'st' };
  if (data === 'st(0)') return { ...result, kind: 'st0' };

  const vectorRmMatch = data.match(/^(xmm|ymm|zmm|mm|k)\/m(\d+)$/);
  if (vectorRmMatch) {
    const cls = vectorRmMatch[1];
    return { ...result, kind: 'rm', size: parseInt(vectorRmMatch[2], 10), regClass: cls };
  }

  const rmMatch = data.match(/^r\/m(\d+)$/);
  if (rmMatch) return { ...result, kind: 'rm', size: parseInt(rmMatch[1], 10), regClass: 'gpr' };

  const split = data.split('/');
  if (split.length === 2) {
    const [lhs, rhs] = split;
    if (lhs.startsWith('r') && rhs.startsWith('m') && lhs.slice(1) === rhs.slice(1)) {
      return { ...result, kind: 'rm', size: parseInt(lhs.slice(1), 10), regClass: 'gpr' };
    }
    if (lhs.startsWith('m') && rhs.startsWith('r') && lhs.slice(1) === rhs.slice(1)) {
      return { ...result, kind: 'rm', size: parseInt(lhs.slice(1), 10), regClass: 'gpr' };
    }
  }

  const regMatch = data.match(/^r(8|16|32|64)$/);
  if (regMatch) return { ...result, kind: 'reg', size: parseInt(regMatch[1], 10), regClass: 'gpr' };

  const memMatch = data.match(/^m(8|16|32|64)$/);
  if (memMatch) return { ...result, kind: 'mem', size: parseInt(memMatch[1], 10) };
  if (data === 'mem' || data === 'm') return { ...result, kind: 'mem', size: 0 };

  const segRegMatch = data.match(/^([a-z]+):z([a-z]+)$/);
  if (segRegMatch) {

    return { ...result, kind: 'string_ptr', segment: segRegMatch[1], base: segRegMatch[2] };
  }

  return null;
}

function buildOperandSignature(operands) {
  if (!operands.length) return '_';
  return operands.map(op => {
    switch (op.kind) {
      case 'reg':
        return op.fixed ? op.fixed : `r${op.size}`;
      case 'rm':
        return `rm${op.size}`;
      case 'mem':
        return `m${op.size}`;
      case 'imm':
        return `imm${op.size}`;
      case 'rel':
        return `rel${op.size}`;
      case 'const':
        return `const${op.value}`;
      default:
        return op.raw || 'unknown';
    }
  }).join(',');
}

function annotateEncoding(operands, encoding) {
  const metadata = {
    opcodeRegisterOperand: -1,
    modrmType: 0,
    modrmRegOperand: -1,
    modrmRmOperand: -1,
    modrmRegConst: -1,
    immediateOperand: -1,
    immediateKind: null
  };

  if (encoding.opcodeReg) {
    const idx = operands.findIndex(op => op.kind === 'reg' || op.kind === 'rm');
    metadata.opcodeRegisterOperand = idx >= 0 ? idx : 0;
  }

  if (encoding.modrm) {
    const modrmToken = encoding.modrm.toUpperCase();

    if (modrmToken === '/R') {
      metadata.modrmType = 1;
    } else if (modrmToken.startsWith('/')) {
      metadata.modrmType = 2;
      metadata.modrmRegConst = parseInt(modrmToken.slice(1), 10);
    }

    if (metadata.modrmRmOperand === -1) {
      let rmIndex = operands.findIndex(op => op.kind === 'rm' || op.kind === 'mem');
      if (rmIndex < 0) rmIndex = 0;
      metadata.modrmRmOperand = rmIndex;
    }

    if (metadata.modrmType === 1 && metadata.modrmRegOperand === -1) {
      metadata.modrmRegOperand = operands.findIndex((op, idx) => idx !== metadata.modrmRmOperand && op.kind === 'reg');
    }
  }

  if (encoding.immSize) {
    metadata.immediateOperand = operands.findIndex(op => op.kind === 'imm' || op.kind === 'rel');
    metadata.immediateKind = encoding.immediateKind || 'imm';
  }

  if (encoding.vex) {
    metadata.vex = {
      vvvvOperand: -1,
      vvvvType: encoding.vex.vvvvType || ''
    };
    const encType = encoding.encodingType || '';
    const vIndex = encType.indexOf('V');
    if (vIndex >= 0) metadata.vex.vvvvOperand = vIndex;
  }

  if (encoding.evex) {
    metadata.evex = {
      vvvvOperand: -1,
      vvvvType: encoding.evex.vvvvType || ''
    };
    const encType = encoding.encodingType || '';
    const vIndex = encType.indexOf('V');
    if (vIndex >= 0) metadata.evex.vvvvOperand = vIndex;
  }

  encoding.metadata = metadata;
}

function generateZeroOperandEmitters(entriesMap) {
  const zeroOpMnemonics = [
    'nop', 'ret',

    'movsb', 'movsw', 'movsq',
    'cmpsb', 'cmpsw', 'cmpsq',
    'scasb', 'scasw', 'scasd', 'scasq',
    'stosb', 'stosw', 'stosd', 'stosq',
    'lodsb', 'lodsw', 'lodsd', 'lodsq'
  ];

  for (const mnemonic of zeroOpMnemonics) {
    const entries = (entriesMap.get(mnemonic) || []).filter(entry => entry.operands.length === 0);
    for (const entry of entries) {
      const variant = entry.variants[0];
      console.log(`void cj_${mnemonic}(cj_ctx* ctx) {`);
      for (const prefix of variant.encoding.prefixes || []) {
        console.log(`  cj_add_u8(ctx, ${hexByte(prefix)});`);
      }
      if (variant.encoding.rexW) {
        console.log(`  emit_rex(ctx, 1, 0, 0, 0);`);
      }
      for (const opcode of variant.encoding.opcodeBytes) {
        console.log(`  cj_add_u8(ctx, ${hexByte(opcode)});`);
      }
      console.log(`}`);
      console.log();
    }
  }
  return zeroOpMnemonics;
}

function generatePushEmitter(entriesMap) {
  const entries = entriesMap.get('push') || [];
  const variants = [];
  for (const entry of entries) {
    for (const variant of entry.variants) {
      variants.push({ entry, variant });
    }
  }

  console.log(`void cj_push(cj_ctx* ctx, cj_operand value) {`);

  const indent = '  ';
  const segmentVariants = variants.filter(({ entry }) => entry.operands[0].kind === 'segment');
  for (const { variant, entry } of segmentVariants) {
    const operand = entry.operands[0];
    const fixed = operand.fixed;
    console.log(`${indent}if (value.type == CJ_REGISTER && value.reg && strcmp(value.reg, "${fixed}") == 0) {`);
    for (const prefix of variant.encoding.prefixes || []) {
      console.log(`${indent}  cj_add_u8(ctx, ${hexByte(prefix)});`);
    }
    emitOpcode(`${indent}  `, variant.encoding);
    console.log(`${indent}  return;`);
    console.log(`${indent}}`);
  }

  const opcodeRegVariants = variants.filter(({ variant }) => variant.encoding.opcodeReg);
  for (const { variant, entry } of opcodeRegVariants) {
    const operand = entry.operands[0];
    const size = operand.size || variant.encoding.operandSize;
    const lastByte = variant.encoding.opcodeBytes.length
      ? variant.encoding.opcodeBytes[variant.encoding.opcodeBytes.length - 1]
      : variant.encoding.opcode;
    console.log(`${indent}if (value.type == CJ_REGISTER && detect_reg_size(value.reg) == ${size}) {`);
    console.log(`${indent}  int8_t reg = parse_reg(value.reg);`);
    console.log(`${indent}  if (reg < 0) return;`);
    for (const prefix of variant.encoding.prefixes || []) {
      console.log(`${indent}  cj_add_u8(ctx, ${hexByte(prefix)});`);
    }
    console.log(`${indent}  uint8_t rex_b = (reg >= 8) ? 1 : 0;`);
    console.log(`${indent}  emit_rex(ctx, ${variant.encoding.rexW ? 1 : 0}, 0, 0, rex_b);`);
    emitOpcode(`${indent}  `, variant.encoding, `${hexByte(lastByte)} + (reg & 7)`);
    console.log(`${indent}  return;`);
    console.log(`${indent}}`);
  }

  const immVariants = variants.filter(({ entry }) => entry.operands[0].kind === 'imm');
  for (const { variant, entry } of immVariants) {
    const operand = entry.operands[0];
    const size = operand.size || variant.encoding.immSize;
    const cast = size === 8 ? 'uint8_t' : size === 16 ? 'uint16_t' : 'uint32_t';
    const maxExpr = size === 8 ? '0xFF' : size === 16 ? '0xFFFF' : '0xFFFFFFFF';
    console.log(`${indent}if (value.type == CJ_CONSTANT && value.constant <= ${maxExpr}) {`);
    for (const prefix of variant.encoding.prefixes || []) {
      console.log(`${indent}  cj_add_u8(ctx, ${hexByte(prefix)});`);
    }
    emitOpcode(`${indent}  `, variant.encoding);
    console.log(`${indent}  cj_add_u${size}(ctx, (${cast})value.constant);`);
    console.log(`${indent}  return;`);
    console.log(`${indent}}`);
  }

  const memVariants = variants.filter(({ entry }) => entry.operands[0].kind === 'rm');
  for (const { variant } of memVariants) {
    const modrmReg = variant.encoding.metadata.modrmRegConst;
    console.log(`${indent}if (value.type == CJ_MEMORY) {`);
    for (const prefix of variant.encoding.prefixes || []) {
      console.log(`${indent}  cj_add_u8(ctx, ${hexByte(prefix)});`);
    }
    console.log(`${indent}  int8_t base_reg = value.mem.base ? parse_reg(value.mem.base) : -1;`);
    console.log(`${indent}  int8_t index_reg = value.mem.index ? parse_reg(value.mem.index) : -1;`);
    console.log(`${indent}  uint8_t rex_x = (index_reg >= 8) ? 1 : 0;`);
    console.log(`${indent}  uint8_t rex_b = (base_reg >= 8) ? 1 : 0;`);
    console.log(`${indent}  emit_rex(ctx, ${variant.encoding.rexW ? 1 : 0}, 0, rex_x, rex_b);`);
    emitOpcode(`${indent}  `, variant.encoding);
    console.log(`${indent}  int mod = emit_memory_modrm(ctx, ${modrmReg}, value.mem.base, value.mem.index, value.mem.scale, value.mem.disp);`);
    console.log(`${indent}  if (mod == 1) cj_add_u8(ctx, (int8_t)value.mem.disp);`);
    console.log(`${indent}  else if (mod == 2) cj_add_u32(ctx, (uint32_t)value.mem.disp);`);
    console.log(`${indent}  return;`);
    console.log(`${indent}}`);
  }

  console.log(`${indent}(void)ctx;`);
  console.log(`${indent}(void)value;`);
  console.log(`}`);
  console.log();
}

function generatePopEmitter(entriesMap) {
  const entries = entriesMap.get('pop') || [];
  const variants = [];
  for (const entry of entries) {
    for (const variant of entry.variants) {
      variants.push({ entry, variant });
    }
  }

  console.log(`void cj_pop(cj_ctx* ctx, cj_operand value) {`);

  const indent = '  ';
  const segmentVariants = variants.filter(({ entry }) => entry.operands[0].kind === 'segment');
  for (const { variant, entry } of segmentVariants) {
    const operand = entry.operands[0];
    const fixed = operand.fixed;
    console.log(`${indent}if (value.type == CJ_REGISTER && value.reg && strcmp(value.reg, "${fixed}") == 0) {`);
    for (const prefix of variant.encoding.prefixes || []) {
      console.log(`${indent}  cj_add_u8(ctx, ${hexByte(prefix)});`);
    }
    emitOpcode(`${indent}  `, variant.encoding);
    console.log(`${indent}  return;`);
    console.log(`${indent}}`);
  }

  const opcodeRegVariants = variants.filter(({ variant }) => variant.encoding.opcodeReg);
  for (const { variant, entry } of opcodeRegVariants) {
    const operand = entry.operands[0];
    const size = operand.size || variant.encoding.operandSize;
    const lastByte = variant.encoding.opcodeBytes.length
      ? variant.encoding.opcodeBytes[variant.encoding.opcodeBytes.length - 1]
      : variant.encoding.opcode;
    console.log(`${indent}if (value.type == CJ_REGISTER && detect_reg_size(value.reg) == ${size}) {`);
    console.log(`${indent}  int8_t reg = parse_reg(value.reg);`);
    console.log(`${indent}  if (reg < 0) return;`);
    for (const prefix of variant.encoding.prefixes || []) {
      console.log(`${indent}  cj_add_u8(ctx, ${hexByte(prefix)});`);
    }
    console.log(`${indent}  uint8_t rex_b = (reg >= 8) ? 1 : 0;`);
    console.log(`${indent}  emit_rex(ctx, ${variant.encoding.rexW ? 1 : 0}, 0, 0, rex_b);`);
    emitOpcode(`${indent}  `, variant.encoding, `${hexByte(lastByte)} + (reg & 7)`);
    console.log(`${indent}  return;`);
    console.log(`${indent}}`);
  }

  const memVariants = variants.filter(({ entry }) => entry.operands[0].kind === 'rm');
  for (const { variant, entry } of memVariants) {
    const modrmReg = variant.encoding.metadata.modrmRegConst;
    const size = entry.operands[0].size || variant.encoding.operandSize;
    console.log(`${indent}if (value.type == CJ_MEMORY) {`);
    for (const prefix of variant.encoding.prefixes || []) {
      console.log(`${indent}  cj_add_u8(ctx, ${hexByte(prefix)});`);
    }
    console.log(`${indent}  int8_t base_reg = value.mem.base ? parse_reg(value.mem.base) : -1;`);
    console.log(`${indent}  int8_t index_reg = value.mem.index ? parse_reg(value.mem.index) : -1;`);
    console.log(`${indent}  uint8_t rex_x = (index_reg >= 8) ? 1 : 0;`);
    console.log(`${indent}  uint8_t rex_b = (base_reg >= 8) ? 1 : 0;`);
    console.log(`${indent}  emit_rex(ctx, ${variant.encoding.rexW ? 1 : 0}, 0, rex_x, rex_b);`);
    emitOpcode(`${indent}  `, variant.encoding);
    console.log(`${indent}  int mod = emit_memory_modrm(ctx, ${modrmReg}, value.mem.base, value.mem.index, value.mem.scale, value.mem.disp);`);
    console.log(`${indent}  if (mod == 1) cj_add_u8(ctx, (int8_t)value.mem.disp);`);
    console.log(`${indent}  else if (mod == 2) cj_add_u32(ctx, (uint32_t)value.mem.disp);`);
    console.log(`${indent}  return;`);
    console.log(`${indent}}`);
  }

  console.log(`${indent}(void)ctx;`);
  console.log(`${indent}(void)value;`);
  console.log(`}`);
  console.log();
}

function detectRegisterSize(name) {
  const info = resolveRegisterInfo(name);
  return info ? info.size : -1;
}

function generateRegisterConstants() {
  let code = '';
  const chunks = [];
  for (let i = 0; i < registers.length; i += 4) {
    const chunk = registers.slice(i, i + 4);
    chunks.push(chunk.map(r =>
      `REG_${r.r64.toUpperCase()} = ${r.encoding}`
    ).join(', '));
  }
  chunks.forEach(chunk => {
    code += `static const uint8_t ${chunk};\n`;
  });
  return code;
}

function generateRegisterHelpers() {
  const lines = [];
  lines.push('static int parse_reg_index(const char* name, const char* prefix, int max) {');
  lines.push('  if (!name || !prefix) return -1;');
  lines.push('  size_t len = strlen(prefix);');
  lines.push('  if (strncmp(name, prefix, len) != 0) return -1;');
  lines.push('  const char* p = name + len;');
  lines.push("  if (*p == '\\0') return -1;");
  lines.push('  char* end = NULL;');
  lines.push('  long value = strtol(p, &end, 10);');
  lines.push("  if (!end || *end != '\\0') return -1;");
  lines.push('  if (value < 0 || value >= max) return -1;');
  lines.push('  return (int)value;');
  lines.push('}');
  lines.push('');
  lines.push('static int is_mmx_reg(const char* name) {');
  lines.push('  return parse_reg_index(name, "mm", 8) >= 0;');
  lines.push('}');
  lines.push('');
  lines.push('static int is_xmm_reg(const char* name) {');
  lines.push('  return parse_reg_index(name, "xmm", 32) >= 0;');
  lines.push('}');
  lines.push('');
  lines.push('static int is_ymm_reg(const char* name) {');
  lines.push('  return parse_reg_index(name, "ymm", 32) >= 0;');
  lines.push('}');
  lines.push('');
  lines.push('static int is_zmm_reg(const char* name) {');
  lines.push('  return parse_reg_index(name, "zmm", 32) >= 0;');
  lines.push('}');
  lines.push('');
  lines.push('static int is_mask_reg(const char* name) {');
  lines.push('  return parse_reg_index(name, "k", 8) >= 0;');
  lines.push('}');
  lines.push('');
  lines.push('static int8_t parse_reg(const char* name) {');
  lines.push('  if (!name) return -1;');
  lines.push('');
  const seenGpr = new Set();
  for (const reg of registers) {
    const entries = [reg.r64, reg.r32, reg.r16, reg.r8, ...reg.aliases];
    for (const entry of entries) {
      if (!entry || seenGpr.has(entry)) continue;
      seenGpr.add(entry);
      lines.push(`  if (strcmp(name, "${entry}") == 0) return REG_${reg.r64.toUpperCase()};`);
    }
  }
  lines.push('  int idx = parse_reg_index(name, "mm", 8);');
  lines.push('  if (idx >= 0) return (int8_t)idx;');
  lines.push('  idx = parse_reg_index(name, "xmm", 32);');
  lines.push('  if (idx >= 0) return (int8_t)idx;');
  lines.push('  idx = parse_reg_index(name, "ymm", 32);');
  lines.push('  if (idx >= 0) return (int8_t)idx;');
  lines.push('  idx = parse_reg_index(name, "zmm", 32);');
  lines.push('  if (idx >= 0) return (int8_t)idx;');
  lines.push('  idx = parse_reg_index(name, "k", 8);');
  lines.push('  if (idx >= 0) return (int8_t)idx;');
  lines.push('  return -1;');
  lines.push('}');
  lines.push('');
  lines.push('static int detect_reg_size(const char* name) {');
  lines.push('  if (!name) return -1;');
  lines.push('  if (is_mmx_reg(name)) return 64;');
  lines.push('  if (is_xmm_reg(name)) return 128;');
  lines.push('  if (is_ymm_reg(name)) return 256;');
  lines.push('  if (is_zmm_reg(name)) return 512;');
  lines.push('  if (is_mask_reg(name)) return 64;');
  const seenSize = new Set();
  for (const reg of registers) {
    const sizeEntries = [
      { label: reg.r64, size: 64 },
      { label: reg.r32, size: 32 },
      { label: reg.r16, size: 16 },
      { label: reg.r8, size: 8 },
      ...reg.aliases.map(alias => ({ label: alias, size: 64 }))
    ];
    for (const entry of sizeEntries) {
      if (!entry.label || seenSize.has(entry.label)) continue;
      seenSize.add(entry.label);
      lines.push(`  if (strcmp(name, "${entry.label}") == 0) return ${entry.size};`);
    }
  }
  lines.push('  return -1;');
  lines.push('}');
  lines.push('');
  return lines.join('\n');
}

function parseEncoding(inst) {
  const parts = inst.opcodeString.split(' ');
  const encoding = {
    prefixes: [],
    rex: { required: false, W: 0, R: 0, X: 0, B: 0 },
    rex: false,
    rexW: false,
    prefix66: false,
    prefix: null,
    opcode: null,
    opcodeBytes: [],
    opcodeReg: false,
    modrm: null,
    immSize: 0,
    immediateKind: null,
    operandSize: 32
  };

  for (const part of parts) {
    const upper = part.toUpperCase();
    if (upper === 'REX.W') {
      encoding.rex = true;
      encoding.rexW = true;
      encoding.rex.required = true;
      encoding.rex.W = 1;
      encoding.operandSize = 64;
    } else if (upper === '66') {
      encoding.prefix66 = true;
      encoding.prefix = 0x66;
      encoding.prefixes.push(0x66);
      encoding.operandSize = 16;
    } else if (['F0', 'F2', 'F3'].includes(upper)) {
      encoding.prefixes.push(parseInt(upper, 16));
    } else if (/^[0-9A-F]{2}$/i.test(part)) {
      const byte = parseInt(upper, 16);
      encoding.opcode = byte;
      encoding.opcodeBytes.push(byte);
    } else if (/^[0-9A-F]{2}\+r$/i.test(part)) {
      const byte = parseInt(upper.substring(0, 2), 16);
      encoding.opcode = byte;
      encoding.opcodeBytes.push(byte);
      encoding.opcodeReg = true;
    } else if (upper.startsWith('/')) {
      encoding.modrm = upper;
    } else if (upper === 'IB') {
      encoding.immSize = 8;
      encoding.immediateKind = 'imm';
    } else if (upper === 'IW') {
      encoding.immSize = 16;
      encoding.immediateKind = 'imm';
    } else if (upper === 'ID') {
      encoding.immSize = 32;
      encoding.immediateKind = 'imm';
    } else if (upper === 'IQ') {
      encoding.immSize = 64;
      encoding.immediateKind = 'imm';
    } else if (upper === 'CB') {
      encoding.immSize = 8;
      encoding.immediateKind = 'rel';
    } else if (upper === 'CW') {
      encoding.immSize = 16;
      encoding.immediateKind = 'rel';
    } else if (upper === 'CD') {
      encoding.immSize = 32;
      encoding.immediateKind = 'rel';
    } else if (upper === 'CQ') {
      encoding.immSize = 64;
      encoding.immediateKind = 'rel';
    }
  }

  if (!encoding.rexW && !encoding.prefix66 && inst.operands.length > 0) {
    const firstOp = inst.operands[0].data;
    if (firstOp && firstOp.includes('r8')) {
      encoding.operandSize = 8;
    }
  }

  if (encoding.immSize === 0 && inst.operands.length === 1) {
    const opData = inst.operands[0].data || '';
    if (opData.startsWith('rel')) {
      const relSize = parseInt(opData.slice(3), 10);
      if (!Number.isNaN(relSize)) {
        encoding.immSize = relSize;
      }
    }
  }

  if (encoding.immSize > 0 && encoding.opcodeBytes.length > 1) {
    encoding.opcodeBytes = encoding.opcodeBytes.slice(0, -1);
  }

  if (inst.operands.length > 0) {
    const primary = inst.operands[0].data || '';
    const sizeMatch = primary.match(/(?:r|m)(8|16|32|64)/);
    if (sizeMatch) {
      encoding.operandSize = parseInt(sizeMatch[1], 10);
    }
  }

  encoding.encodingType = inst.encoding || '';
  const prefixTag = (inst.prefix || '').toUpperCase();
  if (prefixTag === 'VEX') {
    encoding.vex = {
      mm: (inst.mm || '').toUpperCase(),
      pp: (inst.pp || '').toUpperCase(),
      l: (inst.l || '').toUpperCase(),
      w: (inst.w || '').toUpperCase(),
      vvvvType: (inst.vvvv || '').toUpperCase()
    };
  } else if (prefixTag === 'EVEX') {
    encoding.evex = {
      mm: (inst.mm || '').toUpperCase(),
      pp: (inst.pp || '').toUpperCase(),
      l: (inst.l || '').toUpperCase(),
      w: (inst.w || '').toUpperCase(),
      vvvvType: (inst.vvvv || '').toUpperCase()
    };
  }

  return encoding;
}

function emitOpcode(indent, encoding, expression) {
  const bytes = encoding.opcodeBytes.length
    ? encoding.opcodeBytes
    : (encoding.opcode !== null ? [encoding.opcode] : []);
  const prefix = bytes.slice(0, -1);
  const last = bytes.length ? bytes[bytes.length - 1] : null;

  for (const byte of prefix) {
    console.log(`${indent}cj_add_u8(ctx, ${hexByte(byte)});`);
  }

  if (last !== null) {
    console.log(`${indent}cj_add_u8(ctx, ${expression || hexByte(last)});`);
  }
}

console.log(`
#include <string.h>
#include <stdlib.h>
#include "../../ctx.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-label"
`);


console.log(generateRegisterConstants());
console.log(generateRegisterHelpers());
console.log(` 
static void emit_rex(cj_ctx* ctx, uint8_t w, uint8_t r, uint8_t x, uint8_t b) {
  uint8_t rex = 0x40 | (w << 3) | (r << 2) | (x << 1) | b;
  if (rex != 0x40 || w) {
    cj_add_u8(ctx, rex);
  }
}

static void emit_modrm(cj_ctx* ctx, uint8_t mod, uint8_t reg, uint8_t rm) {
  cj_add_u8(ctx, (mod << 6) | (reg << 3) | rm);
}

static void emit_sib(cj_ctx* ctx, uint8_t scale, uint8_t index, uint8_t base) {
  uint8_t scale_bits = 0;
  if (scale == 2) scale_bits = 1;
  else if (scale == 4) scale_bits = 2;
  else if (scale == 8) scale_bits = 3;
  cj_add_u8(ctx, (scale_bits << 6) | (index << 3) | base);
}
`);



console.log(`
static int emit_memory_modrm(cj_ctx* ctx, uint8_t reg, const char* base, const char* index, uint8_t scale, int32_t disp) {
  int8_t base_reg = base ? parse_reg(base) : -1;
  int8_t index_reg = index ? parse_reg(index) : -1;

  uint8_t mod = 0;
  if (disp != 0) {
    if (disp >= -128 && disp <= 127) {
      mod = 1;
    } else {
      mod = 2;
    }
  }

  if (base_reg >= 0 && (base_reg & 7) == 5 && mod == 0) {
    mod = 1;
  }

  int needs_sib = (index_reg >= 0) || (base_reg >= 0 && (base_reg & 7) == 4);

  if (needs_sib) {
    emit_modrm(ctx, mod, reg, 4);

    uint8_t sib_index = (index_reg >= 0) ? (index_reg & 7) : 4;
    uint8_t sib_base = (base_reg >= 0) ? (base_reg & 7) : 5;

    if (base_reg < 0 && mod == 0) {
      mod = 0;
      sib_base = 5;
    }

    emit_sib(ctx, scale, sib_index, sib_base);
  } else {
    uint8_t rm = (base_reg >= 0) ? (base_reg & 7) : 5;
    emit_modrm(ctx, mod, reg, rm);
  }

  return mod;
}
`);

const unaryRmMnemonics = ['not', 'neg', 'inc', 'dec', 'mul', 'div', 'idiv'];
const controlFlowMnemonics = ['call', 'jmp'];
const conditionalJumps = [
  { name: 'jo', enum: 'CJ_COND_O', variants: ['rel8', 'rel32'] },
  { name: 'jno', enum: 'CJ_COND_NO', variants: ['rel8', 'rel32'] },
  { name: 'jb', enum: 'CJ_COND_B', variants: ['rel8', 'rel32'] },
  { name: 'jnb', enum: 'CJ_COND_NB', variants: ['rel8', 'rel32'] },
  { name: 'jz', enum: 'CJ_COND_Z', variants: ['rel8', 'rel32'] },
  { name: 'jnz', enum: 'CJ_COND_NZ', variants: ['rel8', 'rel32'] },
  { name: 'jbe', enum: 'CJ_COND_BE', variants: ['rel8', 'rel32'] },
  { name: 'ja', enum: 'CJ_COND_A', variants: ['rel8', 'rel32'] },
  { name: 'js', enum: 'CJ_COND_S', variants: ['rel8', 'rel32'] },
  { name: 'jns', enum: 'CJ_COND_NS', variants: ['rel8', 'rel32'] },
  { name: 'jp', enum: 'CJ_COND_P', variants: ['rel8', 'rel32'] },
  { name: 'jnp', enum: 'CJ_COND_NP', variants: ['rel8', 'rel32'] },
  { name: 'jl', enum: 'CJ_COND_L', variants: ['rel8', 'rel32'] },
  { name: 'jge', enum: 'CJ_COND_GE', variants: ['rel8', 'rel32'] },
  { name: 'jle', enum: 'CJ_COND_LE', variants: ['rel8', 'rel32'] },
  { name: 'jg', enum: 'CJ_COND_G', variants: ['rel8', 'rel32'] }
];

const labelAwareMnemonics = new Set([
  ...controlFlowMnemonics,
  ...conditionalJumps.map(({ name }) => name),
  'loop',
  'loope',
  'loopne'
]);

const zeroOpGenerated = generateZeroOperandEmitters(entriesByMnemonic);
for (const mnemonic of zeroOpGenerated) {
  generatedMnemonics.add(mnemonic);
}
generatePushEmitter(entriesByMnemonic);
generatedMnemonics.add('push');
generatePopEmitter(entriesByMnemonic);
generatedMnemonics.add('pop');
if (generateEmitterFromEntries('shl', ['dst', 'src'])) generatedMnemonics.add('shl');
if (generateEmitterFromEntries('shr', ['dst', 'src'])) generatedMnemonics.add('shr');
if (generateEmitterFromEntries('sar', ['dst', 'src'])) generatedMnemonics.add('sar');
if (generateEmitterFromEntries('rol', ['dst', 'src'])) generatedMnemonics.add('rol');
if (generateEmitterFromEntries('ror', ['dst', 'src'])) generatedMnemonics.add('ror');
for (const name of ['add', 'sub', 'cmp', 'adc', 'sbb', 'and', 'or', 'xor', 'mov', 'test', 'lea', 'movsx', 'movzx', 'imul']) {
  if (generateEmitterFromEntries(name, ['dst', 'src'])) {
    generatedMnemonics.add(name);
  }
}
const cmovMnemonics = [
  'cmovo', 'cmovno', 'cmovb', 'cmovc', 'cmovnae', 'cmovnb', 'cmovae', 'cmovnc',
  'cmove', 'cmovz', 'cmovne', 'cmovnz', 'cmovbe', 'cmovna', 'cmova', 'cmovnbe',
  'cmovs', 'cmovns', 'cmovp', 'cmovpe', 'cmovnp', 'cmovpo',
  'cmovl', 'cmovnge', 'cmovge', 'cmovnl', 'cmovle', 'cmovng', 'cmovg', 'cmovnle'
];
for (const name of cmovMnemonics) {
  if (generateEmitterFromEntries(name, ['dst', 'src'])) {
    generatedMnemonics.add(name);
  }
}
const setMnemonics = [
  'seto', 'setno', 'setb', 'setc', 'setnae', 'setnb', 'setae', 'setnc',
  'sete', 'setz', 'setne', 'setnz', 'setbe', 'setna', 'seta', 'setnbe',
  'sets', 'setns', 'setp', 'setpe', 'setnp', 'setpo',
  'setl', 'setnge', 'setge', 'setnl', 'setle', 'setng', 'setg', 'setnle'
];
for (const name of setMnemonics) {
  if (generateEmitterFromEntries(name, ['dst'])) {
    generatedMnemonics.add(name);
  }
}
for (const name of ['bt', 'bts', 'btr', 'btc', 'bsf', 'bsr']) {
  if (generateEmitterFromEntries(name, ['dst', 'src'])) {
    generatedMnemonics.add(name);
  }
}
if (generateEmitterFromEntries('bswap', ['value'])) {
  generatedMnemonics.add('bswap');
}
for (const name of ['xchg', 'xadd', 'cmpxchg']) {
  if (generateEmitterFromEntries(name, ['dst', 'src'])) {
    generatedMnemonics.add(name);
  }
}
for (const name of ['cmpxchg8b', 'cmpxchg16b']) {
  if (generateEmitterFromEntries(name, ['dst'])) {
    generatedMnemonics.add(name);
  }
}
const sseArithmetic = ['addps', 'addpd', 'subps', 'subpd', 'mulps', 'mulpd', 'divps', 'divpd'];
const sseLogical = ['andps', 'andpd', 'orps', 'orpd', 'xorps', 'xorpd'];
const sseMovement = ['movss', 'movsd', 'movups', 'movupd', 'movdqu', 'movaps'];
const integerSIMD = ['paddb', 'paddw', 'paddd', 'paddq', 'psubb', 'psubw', 'psubd', 'psubq', 'pand', 'por', 'pxor'];

for (const name of [...sseArithmetic, ...sseLogical, ...sseMovement, ...integerSIMD]) {
  if (generateEmitterFromEntries(name, ['dst', 'src'])) {
    generatedMnemonics.add(name);
  }
}

const avxMoves2 = [
  'vmovss', 'vmovsd', 'vmovaps', 'vmovapd', 'vmovups', 'vmovupd',
  'vmovdqa', 'vmovdqu', 'vmovdqa32', 'vmovdqa64', 'vmovdqu32', 'vmovdqu64',
  'vmovd', 'vmovq', 'vmovhlps', 'vmovlhps', 'vmovhps', 'vmovlps', 'vmovhpd', 'vmovlpd',
  'vmovddup', 'vmovshdup', 'vmovsldup',
  'vbroadcastss', 'vbroadcastsd', 'vbroadcastf128', 'vbroadcasti128',
  'vbroadcastf32x2', 'vbroadcastf32x4', 'vbroadcastf64x2', 'vbroadcastf64x4',
  'vbroadcasti32x2', 'vbroadcasti32x4', 'vbroadcasti64x2', 'vbroadcasti64x4',
  'vsqrtss', 'vsqrtsd', 'vrsqrtss', 'vrcpss',
  'vcvtss2sd', 'vcvtsd2ss', 'vcvtsi2ss', 'vcvtsi2sd',
  'vcvtss2si', 'vcvtsd2si', 'vcvttss2si', 'vcvttsd2si',
  'vcvtps2pd', 'vcvtpd2ps', 'vcvtps2dq', 'vcvtpd2dq',
  'vcvtdq2ps', 'vcvtdq2pd', 'vcvttpd2dq', 'vcvttps2dq',
  'vcomiss', 'vcomisd', 'vucomiss', 'vucomisd'
];
const maskOps2 = ['kmovb', 'kmovw', 'kmovd', 'kmovq', 'knotw', 'knotb', 'knotd', 'knotq'];
for (const name of [...avxMoves2, ...maskOps2]) {
  if (generateEmitterFromEntries(name, ['dst', 'src'])) {
    generatedMnemonics.add(name);
  }
}

const avxZero = ['vzeroall', 'vzeroupper', 'vtestps', 'vtestpd'];
for (const name of avxZero) {
  if (generateEmitterFromEntries(name, [])) {
    generatedMnemonics.add(name);
  }
}

const avxArithmetic3 = [
  'vaddps', 'vaddpd', 'vaddss', 'vaddsd',
  'vsubps', 'vsubpd', 'vsubss', 'vsubsd',
  'vmulps', 'vmulpd', 'vmulss', 'vmulsd',
  'vdivps', 'vdivpd', 'vdivss', 'vdivsd',
  'vminps', 'vminpd', 'vminss', 'vminsd',
  'vmaxps', 'vmaxpd', 'vmaxss', 'vmaxsd',
  'vsqrtps', 'vsqrtpd', 'vrsqrtps', 'vrcpps',
  'vroundps', 'vroundpd', 'vroundss', 'vroundsd',
  'vandps', 'vandpd', 'vandnps', 'vandnpd',
  'vorps', 'vorpd', 'vxorps', 'vxorpd',
  'vhaddps', 'vhaddpd', 'vhsubps', 'vhsubpd',
  'vaddsubps', 'vaddsubpd',
  'vpermilps', 'vpermilpd', 'vperm2f128', 'vperm2i128',
  'vpermd', 'vpermps', 'vpermq', 'vpermpd',
  'vpermb', 'vpermw', 'vpermi2b', 'vpermi2w', 'vpermi2d', 'vpermi2q',
  'vpermi2ps', 'vpermi2pd', 'vpermt2b', 'vpermt2w', 'vpermt2d', 'vpermt2q',
  'vshufps', 'vshufpd', 'vshuff32x4', 'vshuff64x2', 'vshufi32x4', 'vshufi64x2',
  'vblendps', 'vblendpd', 'vblendvps', 'vblendvpd',
  'vpblendw', 'vpblendd', 'vpblendmb', 'vpblendmw', 'vpblendmd', 'vpblendmq',
  'vextractf128', 'vextracti128', 'vextractf32x4', 'vextractf64x2',
  'vextracti32x4', 'vextracti64x2', 'vextractf32x8', 'vextracti32x8',
  'vextractps', 'vinsertf128', 'vinserti128', 'vinsertf32x4', 'vinsertf64x2',
  'vinserti32x4', 'vinserti64x2', 'vinsertf32x8', 'vinserti32x8', 'vinsertps',
  'vcmpps', 'vcmppd', 'vcmpss', 'vcmpsd',
  'vdpps', 'vdppd',
  'vpacksswb', 'vpackssdw', 'vpackuswb', 'vpackusdw',
  'vpunpcklbw', 'vpunpcklwd', 'vpunpckldq', 'vpunpcklqdq',
  'vpunpckhbw', 'vpunpckhwd', 'vpunpckhdq', 'vpunpckhqdq',
  'vunpcklps', 'vunpcklpd', 'vunpckhps', 'vunpckhpd'
];
const avxIntegerSIMD3 = [
  'vpaddb', 'vpaddw', 'vpaddd', 'vpaddq',
  'vpsubb', 'vpsubw', 'vpsubd', 'vpsubq',
  'vpand', 'vpor', 'vpxor', 'vpandn',
  'vpmullw', 'vpmulld', 'vpmullq', 'vpmuldq', 'vpmuludq',
  'vpmulhw', 'vpmulhuw', 'vpmulhrsw',
  'vpminsb', 'vpminsw', 'vpminsd', 'vpminsq',
  'vpminub', 'vpminuw', 'vpminud', 'vpminuq',
  'vpmaxsb', 'vpmaxsw', 'vpmaxsd', 'vpmaxsq',
  'vpmaxub', 'vpmaxuw', 'vpmaxud', 'vpmaxuq',
  'vpsllw', 'vpslld', 'vpsllq', 'vpsllvw', 'vpsllvd', 'vpsllvq',
  'vpsrlw', 'vpsrld', 'vpsrlq', 'vpsrlvw', 'vpsrlvd', 'vpsrlvq',
  'vpsraw', 'vpsrad', 'vpsraq', 'vpsravw', 'vpsravd', 'vpsravq',
  'vpslldq', 'vpsrldq'
];
const avxFMA = [
  'vfmadd132ps', 'vfmadd132pd', 'vfmadd132ss', 'vfmadd132sd',
  'vfmadd213ps', 'vfmadd213pd', 'vfmadd213ss', 'vfmadd213sd',
  'vfmadd231ps', 'vfmadd231pd', 'vfmadd231ss', 'vfmadd231sd',
  'vfmsub132ps', 'vfmsub132pd', 'vfmsub132ss', 'vfmsub132sd',
  'vfmsub213ps', 'vfmsub213pd', 'vfmsub213ss', 'vfmsub213sd',
  'vfmsub231ps', 'vfmsub231pd', 'vfmsub231ss', 'vfmsub231sd',
  'vfnmadd132ps', 'vfnmadd132pd', 'vfnmadd132ss', 'vfnmadd132sd',
  'vfnmadd213ps', 'vfnmadd213pd', 'vfnmadd213ss', 'vfnmadd213sd',
  'vfnmadd231ps', 'vfnmadd231pd', 'vfnmadd231ss', 'vfnmadd231sd',
  'vfnmsub132ps', 'vfnmsub132pd', 'vfnmsub132ss', 'vfnmsub132sd',
  'vfnmsub213ps', 'vfnmsub213pd', 'vfnmsub213ss', 'vfnmsub213sd',
  'vfnmsub231ps', 'vfnmsub231pd', 'vfnmsub231ss', 'vfnmsub231sd'
];
const maskOps3 = [
  'kandw', 'kandb', 'kandd', 'kandq',
  'korw', 'korb', 'kord', 'korq',
  'kxorw', 'kxorb', 'kxord', 'kxorq',
  'kaddw', 'kaddb', 'kaddd', 'kaddq',
  'ktestw', 'ktestb', 'ktestd', 'ktestq'
];
const avxGather = [
  'vgatherdps', 'vgatherdpd', 'vgatherqps', 'vgatherqpd',
  'vpgatherdd', 'vpgatherdq', 'vpgatherqd', 'vpgatherqq'
];

for (const name of [...avxArithmetic3, ...avxIntegerSIMD3, ...avxFMA, ...maskOps3, ...avxGather]) {
  if (generateEmitterFromEntries(name, ['dst', 'src1', 'src2'])) {
    generatedMnemonics.add(name);
  }
}
for (const name of unaryRmMnemonics) {
  if (generateEmitterFromEntries(name, ['value'])) {
    generatedMnemonics.add(name);
  }
}
for (const name of controlFlowMnemonics) {
  if (generateEmitterFromEntries(name, ['target'])) {
    generatedMnemonics.add(name);
  }
}
for (const {name} of conditionalJumps) {
  if (generateEmitterFromEntries(name, ['target'])) {
    generatedMnemonics.add(name);
  }
}

for (const name of ['loop', 'loope', 'loopne']) {
  if (generateEmitterFromEntries(name, ['target'])) {
    generatedMnemonics.add(name);
  }
}

if (generateEmitterFromEntries('leave', [])) {
  generatedMnemonics.add('leave');
}
if (generateEmitterFromEntries('enter', ['size', 'nesting'])) {
  generatedMnemonics.add('enter');
}

for (const name of ['shld', 'shrd']) {
  if (generateEmitterFromEntries(name, ['dst', 'src', 'count'])) {
    generatedMnemonics.add(name);
  }
}

for (const name of ['cbw', 'cwde', 'cdqe', 'cwd', 'cdq', 'cqo']) {
  if (generateEmitterFromEntries(name, [])) {
    generatedMnemonics.add(name);
  }
}

for (const name of ['clc', 'cld', 'cmc', 'lahf', 'popf', 'pushf', 'sahf', 'stc', 'std', 'sti', 'cli']) {
  if (generateEmitterFromEntries(name, [])) {
    generatedMnemonics.add(name);
  }
}

for (const name of ['lfence', 'mfence', 'sfence']) {
  if (generateEmitterFromEntries(name, [])) {
    generatedMnemonics.add(name);
  }
}

for (const name of ['lzcnt', 'popcnt', 'tzcnt']) {
  if (generateEmitterFromEntries(name, ['dst', 'src'])) {
    generatedMnemonics.add(name);
  }
}

if (generateEmitterFromEntries('movbe', ['dst', 'src'])) {
  generatedMnemonics.add('movbe');
}

for (const name of ['cpuid', 'rdtsc', 'rdtscp']) {
  if (generateEmitterFromEntries(name, [])) {
    generatedMnemonics.add(name);
  }
}

for (const name of ['pause', 'int3', 'ud2']) {
  if (generateEmitterFromEntries(name, [])) {
    generatedMnemonics.add(name);
  }
}

for (const name of ['blsi', 'blsmsk', 'blsr']) {
  if (generateEmitterFromEntries(name, ['dst', 'src'])) {
    generatedMnemonics.add(name);
  }
}

for (const name of ['andn', 'bextr', 'bzhi', 'mulx', 'pdep', 'pext', 'sarx', 'shlx', 'shrx']) {
  if (generateEmitterFromEntries(name, ['dst', 'src1', 'src2'])) {
    generatedMnemonics.add(name);
  }
}

if (generateEmitterFromEntries('rorx', ['dst', 'src', 'imm'])) {
  generatedMnemonics.add('rorx');
}

for (const name of ['aesdec', 'aesdeclast', 'aesenc', 'aesenclast', 'aesimc',
                     'sha1msg1', 'sha1msg2', 'sha1nexte', 'sha256msg1', 'sha256msg2']) {
  if (generateEmitterFromEntries(name, ['dst', 'src'])) {
    generatedMnemonics.add(name);
  }
}

for (const name of ['aeskeygenassist', 'sha1rnds4']) {
  if (generateEmitterFromEntries(name, ['dst', 'src', 'imm'])) {
    generatedMnemonics.add(name);
  }
}

if (generateEmitterFromEntries('sha256rnds2', ['dst', 'src1', 'src2'])) {
  generatedMnemonics.add('sha256rnds2');
}

for (const name of [
  'addsubpd', 'addsubps', 'haddpd', 'haddps', 'hsubpd', 'hsubps',
  'lddqu', 'movshdup', 'movsldup',
  'pabsb', 'pabsd', 'pabsw',
  'phaddd', 'phaddsw', 'phaddw', 'phsubd', 'phsubsw', 'phsubw',
  'pmaddubsw', 'pmulhrsw', 'pmulhrw', 'pshufb',
  'psignb', 'psignd', 'psignw',
  'packusdw', 'movntdqa',
  'pcmpeqb', 'pcmpeqd', 'pcmpeqq', 'pcmpeqw',
  'pcmpgtb', 'pcmpgtd', 'pcmpgtq', 'pcmpgtw',
  'ptest',
  'pminsb', 'pmaxsb', 'pminsd', 'pmaxsd', 'pminsw', 'pmaxsw',
  'pminub', 'pmaxub', 'pminud', 'pmaxud', 'pminuw', 'pmaxuw',
  'pmuldq', 'pmulld',
  'pmovsxbd', 'pmovsxbq', 'pmovsxbw',
  'pmovzxbd', 'pmovzxbq', 'pmovzxbw',
  'pmulhuw', 'pmulhw', 'pmullw', 'pmuludq',
  'phminposuw'
]) {
  if (generateEmitterFromEntries(name, ['dst', 'src'])) {
    generatedMnemonics.add(name);
  }
}

for (const name of [
  'blendpd', 'blendps', 'blendvpd', 'blendvps',
  'dppd', 'dpps', 'extractps', 'insertps',
  'mpsadbw', 'palignr', 'pblendvb', 'pblendw',
  'pshufd', 'pshufhw', 'pshuflw', 'pshufw',
  'roundpd', 'roundps', 'roundsd', 'roundss'
]) {
  if (generateEmitterFromEntries(name, ['dst', 'src', 'imm'])) {
    generatedMnemonics.add(name);
  } else if (generateEmitterFromEntries(name, ['dst', 'src1', 'src2'])) {
    generatedMnemonics.add(name);
  }
}

for (const name of ['pcmpestri', 'pcmpestrm', 'pcmpistri', 'pcmpistrm']) {
  if (generateEmitterFromEntries(name, ['dst', 'src', 'imm'])) {
    generatedMnemonics.add(name);
  }
}

const remainingAVX = [
  'vaesdec', 'vaesdeclast', 'vaesenc', 'vaesenclast', 'vaesimc', 'vaeskeygenassist',
  'valignd', 'valignq',
  'vblendmb', 'vblendmd', 'vblendmpd', 'vblendmps', 'vblendmq', 'vblendmw',
  'vbroadcastf32x8', 'vbroadcasti32x8',
  'vcompresspd', 'vcompressps',
  'vcvtpd2qq', 'vcvtpd2udq', 'vcvtpd2uqq', 'vcvtph2ps', 'vcvtps2ph', 'vcvtps2qq', 'vcvtps2udq', 'vcvtps2uqq',
  'vcvtqq2pd', 'vcvtqq2ps', 'vcvtsd2usi', 'vcvtss2usi',
  'vcvttpd2qq', 'vcvttpd2udq', 'vcvttpd2uqq', 'vcvttps2qq', 'vcvttps2udq', 'vcvttps2uqq',
  'vcvttsd2usi', 'vcvttss2usi', 'vcvtudq2pd', 'vcvtudq2ps', 'vcvtuqq2pd', 'vcvtuqq2ps',
  'vcvtusi2sd', 'vcvtusi2ss',
  'vdbpsadbw',
  'vexp2pd', 'vexp2ps', 'vexpandpd', 'vexpandps',
  'vextractf64x4', 'vextracti64x4',
  'vfixupimmpd', 'vfixupimmps', 'vfixupimmsd', 'vfixupimmss',
  'vfmaddpd', 'vfmaddps', 'vfmaddsd', 'vfmaddss',
  'vfmaddsub132pd', 'vfmaddsub132ps', 'vfmaddsub213pd', 'vfmaddsub213ps', 'vfmaddsub231pd', 'vfmaddsub231ps',
  'vfmaddsubpd', 'vfmaddsubps',
  'vfmsubadd132pd', 'vfmsubadd132ps', 'vfmsubadd213pd', 'vfmsubadd213ps', 'vfmsubadd231pd', 'vfmsubadd231ps',
  'vfmsubaddpd', 'vfmsubaddps', 'vfmsubpd', 'vfmsubps', 'vfmsubsd', 'vfmsubss',
  'vfnmaddpd', 'vfnmaddps', 'vfnmaddsd', 'vfnmaddss',
  'vfnmsubpd', 'vfnmsubps', 'vfnmsubsd', 'vfnmsubss',
  'vfpclasspd', 'vfpclassps', 'vfpclasssd', 'vfpclassss',
  'vfrczpd', 'vfrczps', 'vfrczsd', 'vfrczss',
  'vgatherpf0dpd', 'vgatherpf0dps', 'vgatherpf0qpd', 'vgatherpf0qps',
  'vgatherpf1dpd', 'vgatherpf1dps', 'vgatherpf1qpd', 'vgatherpf1qps',
  'vgetexppd', 'vgetexpps', 'vgetexpsd', 'vgetexpss',
  'vgetmantpd', 'vgetmantps', 'vgetmantsd', 'vgetmantss',
  'vinsertf64x4', 'vinserti64x4',
  'vlddqu', 'vldmxcsr',
  'vmaskmovdqu', 'vmaskmovpd', 'vmaskmovps',
  'vmovdqu16', 'vmovdqu8', 'vmovmskpd', 'vmovmskps',
  'vmovntdq', 'vmovntdqa', 'vmovntpd', 'vmovntps',
  'vmpsadbw',
  'vpabsb', 'vpabsd', 'vpabsq', 'vpabsw',
  'vpaddsb', 'vpaddsw', 'vpaddusb', 'vpaddusw',
  'vpalignr',
  'vpandd', 'vpandnd', 'vpandnq', 'vpandq',
  'vpavgb', 'vpavgw',
  'vpblendvb',
  'vpbroadcastb', 'vpbroadcastd', 'vpbroadcastmb2d', 'vpbroadcastmb2q', 'vpbroadcastq', 'vpbroadcastw',
  'vpclmulqdq', 'vpcmov',
  'vpcmpb', 'vpcmpd', 'vpcmpeqb', 'vpcmpeqd', 'vpcmpeqq', 'vpcmpeqw',
  'vpcmpestri', 'vpcmpestrm', 'vpcmpgtb', 'vpcmpgtd', 'vpcmpgtq', 'vpcmpgtw',
  'vpcmpistri', 'vpcmpistrm',
  'vpcmpq', 'vpcmpub', 'vpcmpud', 'vpcmpuq', 'vpcmpuw', 'vpcmpw',
  'vpcomb', 'vpcomd', 'vpcompressd', 'vpcompressq', 'vpcomq',
  'vpcomub', 'vpcomud', 'vpcomuq', 'vpcomuw', 'vpcomw',
  'vpconflictd', 'vpconflictq',
  'vpermil2pd', 'vpermil2ps', 'vpermt2pd', 'vpermt2ps',
  'vpexpandd', 'vpexpandq',
  'vpextrb', 'vpextrd', 'vpextrq', 'vpextrw',
  'vphaddbd', 'vphaddbq', 'vphaddbw', 'vphaddd', 'vphadddq', 'vphaddsw',
  'vphaddubd', 'vphaddubq', 'vphaddubw', 'vphaddudq', 'vphadduwd', 'vphadduwq',
  'vphaddw', 'vphaddwd', 'vphaddwq', 'vphminposuw',
  'vphsubbw', 'vphsubd', 'vphsubdq', 'vphsubsw', 'vphsubw', 'vphsubwd',
  'vpinsrb', 'vpinsrd', 'vpinsrq', 'vpinsrw',
  'vplzcntd', 'vplzcntq',
  'vpmacsdd', 'vpmacsdqh', 'vpmacsdql', 'vpmacssdd', 'vpmacssdqh', 'vpmacssdql',
  'vpmacsswd', 'vpmacssww', 'vpmacswd', 'vpmacsww',
  'vpmadcsswd', 'vpmadcswd',
  'vpmadd52huq', 'vpmadd52luq', 'vpmaddubsw', 'vpmaddwd',
  'vpmaskmovd', 'vpmaskmovq',
  'vpmovb2m', 'vpmovd2m', 'vpmovdb', 'vpmovdw',
  'vpmovm2b', 'vpmovm2d', 'vpmovm2q', 'vpmovm2w',
  'vpmovmskb', 'vpmovq2m', 'vpmovqb', 'vpmovqd', 'vpmovqw',
  'vpmovsdb', 'vpmovsdw', 'vpmovsqb', 'vpmovsqd', 'vpmovsqw', 'vpmovswb',
  'vpmovsxbd', 'vpmovsxbq', 'vpmovsxbw', 'vpmovsxdq', 'vpmovsxwd', 'vpmovsxwq',
  'vpmovusdb', 'vpmovusdw', 'vpmovusqb', 'vpmovusqd', 'vpmovusqw', 'vpmovuswb',
  'vpmovw2m', 'vpmovwb',
  'vpmovzxbd', 'vpmovzxbq', 'vpmovzxbw', 'vpmovzxdq', 'vpmovzxwd', 'vpmovzxwq',
  'vpmultishiftqb',
  'vpord', 'vporq', 'vpperm',
  'vprold', 'vprolq', 'vprolvd', 'vprolvq',
  'vprord', 'vprorq', 'vprorvd', 'vprorvq',
  'vprotb', 'vprotd', 'vprotq', 'vprotw',
  'vpsadbw',
  'vpscatterdd', 'vpscatterdq', 'vpscatterqd', 'vpscatterqq',
  'vpshab', 'vpshad', 'vpshaq', 'vpshaw',
  'vpshlb', 'vpshld', 'vpshlq', 'vpshlw',
  'vpshufb', 'vpshufd', 'vpshufhw', 'vpshuflw',
  'vpsignb', 'vpsignd', 'vpsignw',
  'vpsubsb', 'vpsubsw', 'vpsubusb', 'vpsubusw',
  'vpternlogd', 'vpternlogq',
  'vptest',
  'vptestmb', 'vptestmd', 'vptestmq', 'vptestmw',
  'vptestnmb', 'vptestnmd', 'vptestnmq', 'vptestnmw',
  'vpxord', 'vpxorq',
  'vrangepd', 'vrangeps', 'vrangesd', 'vrangess',
  'vrcp14pd', 'vrcp14ps', 'vrcp14sd', 'vrcp14ss',
  'vrcp28pd', 'vrcp28ps', 'vrcp28sd', 'vrcp28ss',
  'vreducepd', 'vreduceps', 'vreducesd', 'vreducess',
  'vrndscalepd', 'vrndscaleps', 'vrndscalesd', 'vrndscaless',
  'vrsqrt14pd', 'vrsqrt14ps', 'vrsqrt14sd', 'vrsqrt14ss',
  'vrsqrt28pd', 'vrsqrt28ps', 'vrsqrt28sd', 'vrsqrt28ss',
  'vscalefpd', 'vscalefps', 'vscalefsd', 'vscalefss',
  'vscatterdpd', 'vscatterdps',
  'vscatterpf0dpd', 'vscatterpf0dps', 'vscatterpf0qpd', 'vscatterpf0qps',
  'vscatterpf1dpd', 'vscatterpf1dps', 'vscatterpf1qpd', 'vscatterpf1qps',
  'vscatterqpd', 'vscatterqps',
  'vstmxcsr'
];

for (const name of remainingAVX) {
  if (generateEmitterFromEntries(name, ['dst', 'src'])) {
    generatedMnemonics.add(name);
  } else if (generateEmitterFromEntries(name, ['dst', 'src1', 'src2'])) {
    generatedMnemonics.add(name);
  } else if (generateEmitterFromEntries(name, ['dst', 'src', 'imm'])) {
    generatedMnemonics.add(name);
  } else if (generateEmitterFromEntries(name, ['dst', 'src1', 'src2', 'imm'])) {
    generatedMnemonics.add(name);
  } else if (generateEmitterFromEntries(name, ['dst'])) {
    generatedMnemonics.add(name);
  } else if (generateEmitterFromEntries(name, [])) {
    generatedMnemonics.add(name);
  }
}

const fpuInstructions = [
  'f2xm1', 'fabs', 'fadd', 'faddp', 'fbld', 'fbstp', 'fchs', 'fclex',
  'fcmovb', 'fcmovbe', 'fcmove', 'fcmovnb', 'fcmovnbe', 'fcmovne', 'fcmovnu', 'fcmovu',
  'fcom', 'fcomi', 'fcomip', 'fcomp', 'fcompp', 'fcos', 'fdecstp',
  'fdiv', 'fdivp', 'fdivr', 'fdivrp', 'femms', 'ffree',
  'fiadd', 'ficom', 'ficomp', 'fidiv', 'fidivr', 'fild', 'fimul',
  'fincstp', 'finit', 'fist', 'fistp', 'fisttp', 'fisub', 'fisubr',
  'fld', 'fld1', 'fldcw', 'fldenv', 'fldl2e', 'fldl2t', 'fldlg2', 'fldln2', 'fldpi', 'fldz',
  'fmul', 'fmulp', 'fnclex', 'fninit', 'fnop', 'fnsave', 'fnstcw', 'fnstenv', 'fnstsw',
  'fpatan', 'fprem', 'fprem1', 'fptan', 'frndint', 'frstor', 'fsave', 'fscale',
  'fsin', 'fsincos', 'fsqrt', 'fst', 'fstcw', 'fstenv', 'fstp', 'fstsw',
  'fsub', 'fsubp', 'fsubr', 'fsubrp', 'ftst',
  'fucom', 'fucomi', 'fucomip', 'fucomp', 'fucompp',
  'fwait', 'fxam', 'fxch', 'fxrstor', 'fxrstor64', 'fxsave', 'fxsave64',
  'fxtract', 'fyl2x', 'fyl2xp1'
];

for (const name of fpuInstructions) {

  if (generateEmitterFromEntries(name, [])) {
    generatedMnemonics.add(name);
  } else if (generateEmitterFromEntries(name, ['dst'])) {
    generatedMnemonics.add(name);
  } else if (generateEmitterFromEntries(name, ['dst', 'src'])) {
    generatedMnemonics.add(name);
  }
}

generateLabelWrappers(labelAwareMnemonics);

console.log(`void cj_jcc(cj_ctx* ctx, cj_condition cond, cj_operand target) {`);
console.log(`  switch (cond) {`);
for (const {name, enum: enumName} of conditionalJumps) {
  console.log(`    case ${enumName}:`);
  console.log(`      cj_${name}(ctx, target);`);
  console.log(`      break;`);
}
console.log(`    default:`);
console.log(`      (void)ctx;`);
console.log(`      (void)target;`);
console.log(`      break;`);
console.log(`  }`);
console.log(`}`);
console.log('');

console.log('#pragma GCC diagnostic pop');

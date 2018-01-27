(*
  fastMD5 algorithm by Maxim Masiutin
  https://github.com/maximmasiutin/MD5_Transform-x64

  delphi imp by 600585@qq.com
  https://github.com/PassByYou888/ZServer4D
*)

unit Fast_MD5;

interface

{$IF Defined(MSWINDOWS)}

type
  TMD5 = array [0 .. 15] of byte;
  PMD5 = ^TMD5;
function FastMD5(const BuffPtr: PBYTE; BufSiz: NativeUInt): TMD5;
{$IFEND}

implementation

{$IF Defined(MSWINDOWS)}
(*
  fastMD5 algorithm by Maxim Masiutin
  https://github.com/maximmasiutin/MD5_Transform-x64

  delphi imp by 600585@qq.com
  https://github.com/PassByYou888/ZServer4D
*)

{$IF Defined(WIN32)}
(*
  ; ==============================================================
  ;
  ; MD5_386.Asm   -  386 optimized helper routine for calculating
  ;                  MD Message-Digest values
  ; written 2/2/94 by
  ;
  ; Peter Sawatzki
  ; Buchenhof 3
  ; D58091 Hagen, Germany Fed Rep
  ;
  ; EMail: Peter@Sawatzki.de
  ; EMail: 100031.3002@compuserve.com
  ; WWW:   http://www.sawatzki.de
  ;
  ;
  ; original C Source was found in Dr. Dobbs Journal Sep 91
  ; MD5 algorithm from RSA Data Security, Inc.
*)
{$LINK MD5_32.obj}
{$ELSEIF Defined(WIN64)}
(*
  ; MD5_Transform-x64
  ; MD5 transform routine oprimized for x64 processors
  ; Copyright 2018 Ritlabs, SRL
  ; The 64-bit version is written by Maxim Masiutin <max@ritlabs.com>

  ; The main advantage of this 64-bit version is that
  ; it loads 64 bytes of hashed message into 8 64-bit registers
  ; (RBP, R8, R9, R10, R11, R12, R13, R14) at the beginning,
  ; to avoid excessive memory load operations
  ; througout the routine.

  ; To operate with 32-bit values store in higher bits
  ; of a 64-bit register (bits 32-63) uses "Ror" by 32;
  ; 8 macro variables (M1-M8) are used to keep record
  ; or corrent state of whether the register has been
  ; Ror'ed or not.

  ; It also has an ability to use Lea instruction instead
  ; of two sequental Adds (uncomment UseLea=1), but it is
  ; slower on Skylake processors. Also, Intel in the
  ; Optimization Reference Maual discourages us of
  ; Lea as a replacement of two adds, since it is slower
  ; on the Atom processors.

  ; MD5_Transform-x64 is released under a dual license,
  ; and you may choose to use it under either the
  ; Mozilla Public License 2.0 (MPL 2.1, available from
  ; https://www.mozilla.org/en-US/MPL/2.0/) or the
  ; GNU Lesser General Public License Version 3,
  ; dated 29 June 2007 (LGPL 3, available from
  ; https://www.gnu.org/licenses/lgpl.html).

  ; MD5_Transform-x64 is based
  ; on the following code by Peter Sawatzki.

  ; The original notice by Peter Sawatzki follows.
*)
{$LINK MD5_64.obj}
{$IFEND}
procedure MD5_Transform(var Accu; const Buf); register; external;

function FastMD5(const BuffPtr: PBYTE; BufSiz: NativeUInt): TMD5;
var
  CDigest: TMD5;
  BitLo, BitHi: Cardinal;
  p: PBYTE;
  rest, WorkLen: byte;
  WorkBuf: array [0 .. 63] of byte;
begin
  BitLo := 0;
  BitHi := 0;
  rest := 0;
  PCardinal(@CDigest[0])^ := $67452301;
  PCardinal(@CDigest[4])^ := $EFCDAB89;
  PCardinal(@CDigest[8])^ := $98BADCFE;
  PCardinal(@CDigest[12])^ := $10325476;

  if BitLo + BufSiz shl 3 < BitLo then
    Inc(BitHi);

  Inc(BitLo, BufSiz shl 3);
  Inc(BitHi, BufSiz shr (SizeOf(BufSiz) * 8 - 3));

  p := BuffPtr;

  while BufSiz >= $40 do
  begin
    MD5_Transform(CDigest, p^);
    Inc(p, $40);
    Dec(BufSiz, $40)
  end;
  if BufSiz > 0 then
  begin
    rest := BufSiz;
    move(p^, WorkBuf[0], rest)
  end;

  Result := PMD5(@CDigest[0])^;
  WorkBuf[rest] := $80;
  WorkLen := rest + 1;
  if WorkLen > $38 then
  begin
    if WorkLen < $40 then
      FillChar(WorkBuf[WorkLen], $40 - WorkLen, 0);
    MD5_Transform(Result, WorkBuf);
    WorkLen := 0
  end;
  FillChar(WorkBuf[WorkLen], $38 - WorkLen, 0);
  PCardinal(@WorkBuf[$38])^ := BitLo;
  PCardinal(@WorkBuf[$3C])^ := BitHi;
  MD5_Transform(Result, WorkBuf);
end;

{$IFEND}

end.

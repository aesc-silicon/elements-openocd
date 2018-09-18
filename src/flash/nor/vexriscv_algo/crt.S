.global crtStart
.global main

crtStart:
  la sp, _stack_start
  call main
  ebreak

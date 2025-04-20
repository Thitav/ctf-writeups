## First

The program asks for a G-code command, so, by searching for a G-code documentation, I found [this](https://marlinfw.org/meta/gcode/).
After fuzzing the binary with all gcode commands, i found out that only the following commands were implemented:
```
Code    Função
G0 X[x] Y[y] Z[z] E[e]  Movimento rápido sem extrusão. Move o cabeçote rapidamente até a posição informada.
G1 X[x] Y[y] Z[z] E[e]   Movimento linear com controle de extrusão. Move o cabeçote até a posição com velocidade controlada.
G28    Home All Axes — envia o cabeçote de volta para a posição zero (origem).
G90    Posicionamento absoluto — coordenadas subsequentes são interpretadas como absolutas em relação à origem.
G91    Posicionamento relativo — coordenadas são relativas à posição atual.
G92    Define a posição atual como (0, 0, 0) ou outra definida. Útil para calibrar o ponto de origem manualmente.
M1    Pausa indefinida (Sleep) — pausa a execução até ser retomado manualmente.
M33    Parece acessar /flag.txt, pode ser parte de algum recurso customizado ou Easter egg.
M82    Define o modo do extrusor como absoluto — comandos de extrusão usam valores absolutos.
M83    Define o modo do extrusor como relativo — comandos de extrusão usam valores relativos.
M84    Desliga os motores (stop idle hold) — útil após finalização da impressão.
M104 S[s] Define a temperatura do extrusor. No seu simulador, causou um panic: attempt to use null value, então algo relacionado a termistor ou extrusor está mal implementado.
M105    Lê a temperatura atual do extrusor e da mesa. No seu simulador retornou: ok T:0 B:0 V:0.
M106    Liga a ventoinha (fan on).
M107    Desliga a ventoinha (fan off).
M109  S[s] Aguarda até a temperatura do extrusor atingir o valor definido. No seu simulador, isso também causou um panic.
M140  S[s]  Define a temperatura da mesa aquecida (bed). Também causou erro (null value).
M190  S[s] Aguarda até a temperatura da mesa ser atingida. Também resultou em panic.
```
After some testing, i found out that most commands dont do nothing, but after using `G0 X999 Y999 Z999` and `M105`, I got a segmentation fault.
As this could be interesting, i decided to reverse engineer the binary using IDA pro, from which i found the following function causing the segfault:
```C
__int64 *__fastcall read_array(__int64 *out, __int64 *pos)
{
  __int64 *result; // rax
  char value; // cl

  result = out;
  value = *(_BYTE *)(62500 * pos[0] + 250 * pos[1] + pos[2] + pos[7]);
  *(_WORD *)out = 0;
  *((_BYTE *)out + 2) = value;
  return result;
}
```
We can cleary see that the function is reading 1 byte from an array with dimensions of 250x250x250 using the position set by `G0` and `G1`. After more testing, i also found out that using `G1` in coordinates out of the array boundaries caused a segfault, leading to this function:
```C
__int64 __fastcall add_array(__int64 *pos, char value)
{
  __int64 addr; // [rsp+18h] [rbp-20h]
  _BYTE read_value[4]; // [rsp+34h] [rbp-4h] BYREF

  addr = 62500 * pos[0] + 250 * pos[1] + pos[2] + pos[7];
  read_array((__int64)read_value, pos);
  *(_BYTE *)(addr) = value + read_value[2];
  return 0;
}

```
The function calls `read_array`, reading the value stored at coordinate, then adding the desired value to the read value and storing the result at the same position.
By using `G1` and `M105` we can prove that behaviour:
```
 > Enter G-code:
G1 X0 Y0 Z0 E5
 > Linearly setting position to (0, 0, 0) 0
M105      
 > ok T:0 B:0 V:5
G1 X0 Y0 Z0 E1
 > Linearly setting position to (0, 0, 0) 0
M105
 > ok T:0 B:0 V:6
```
We can see that `G1` is adding the value to the coordinate, which we can read throught the value outputted by `M105` (`V:[value]`).
With all that in mind, we can read and write to any memory address. For exploiting this, i used IDA debugger again for finding address leaks on the `.bss` section (the same section of the array), making it possible to write a rop chain for calling `execve("/bin/sh")` and ovewriting some arbitrary function return address with the chain.
Finding the gadgets for the chain was pretty easy, sinc the binary is statically linked with [MUSL](https://musl.libc.org/) libc. Also, for picking the right function to overwrite its return address, was pretty simple, since the only restriction was to pick a function that didnt return before quitting the program (since we can only write 1 byte at a time, we cant rely on functions that return every time we input data or read/write values).


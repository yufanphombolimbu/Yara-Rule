/*
   YARA Rule Set
   Author: R3dPanda \n yara rule for dharma ransomware info.hta file
   Date: 2023-03-30
   Identifier: Dharama
   Reference: Internal Resources
   License: License by R3dPanda
*/

/* Rule Set ----------------------------------------------------------------- */

rule _home_kali_threat_hunting_yarGen_Dharama_Info {
   meta:
      description = "Dharama - file Info.hta"
      author = "R3dPanda \n yara rule for dharma ransomware info.hta file"
      reference = "Internal Resources"
      date = "2023-03-30"
      hash1 = "691c43d699d3b573e6ce83a6ec9bc94cfc31358bf7d67fdc13191817090a4af3"
   strings:
      $s1 = "      ICON='msiexec.exe'" fullword ascii /* score: '19.00'*/
      $s2 = "JLuui6qquyzLuvv48eP/F9gyjteWIvjw4cN/BHwafE95//79DA2lGB3dy9CQydiYtWrPWFEULMsiFAoRiUSIRCJEo1EikQihUKid4VIUBdd1V0puXAEhIBrVcBwwjDiu" ascii /* score: '16.00'*/
      $s3 = "AfyrL37xiz/o0yn1DW8rgg8ePDimadqfAwfp6rtpmoyPj5NIJNB1HV0PYZoRDCOMrofQNANFUbt2kXiei+M0aTZr2HaVRqOCbdewbZtCocDi4uJK0v1lVVU//cQTTywM" ascii /* score: '14.00'*/
      $s4 = "bjX+j6UpN2y0rW10kC67v/ifL+b/cqHkFoELQAM4zhrV9IYHE7+x0Jh85aL9g2RYMcKGEjFUhoQQ18Eg5cHD9ahmyu7rL16oP/2Zfyh8s9KUDWAG/x1Ck/ijF9eEXhlK" ascii /* score: '11.00'*/
      $s5 = "QNyLvbC7c+7cM328/NHTM7PAAtxjZnYJ7beqa3r6eP26v/27X3fDNraxjW1sYxvb2AyIze5Av3Hw4MExVVVTiqIkgYTneUJRlLyiKIVGo5F96qmnFje7j/3EdUXwo48+" ascii /* score: '11.00'*/
      $s6 = "nwygJGB4gGpaBDa4dwz3juDA0W0H630mVwJLi8seEf2TX/1Rb84lSGLVgKYC1oDCpa2ayfK1SqA+la7Xs8hOVitQzzJYJrqcrVYoFKji7lBopW2C5blLq38GeL0oKhAa" ascii /* score: '11.00'*/
      $s7 = "2/bs2fNAMpm8H9Acx+HcuXNMTEzgeS6e53H0KNxzzx5M00BKSb1eJ5VKcbUQNxKBRiOGaUYZHx9nenoaRVGse++999Bzzz03CZzrzSVcHQYuwY8//ri2tLT0FSCmqip7" ascii /* score: '11.00'*/
      $s8 = "9uwhmbyRaNTCslbeJxKJEIvFMAyj7fC89tpFMplFstnJto0NUCqVjr344ot/ceTIkR8vLCykPc8rA3lgCcgBS57nlRYWFubffPPN17LZ7Mujo6NjpmnuACiXy9i2jWGA" ascii /* score: '11.00'*/
      $s9 = "yta0wT664mDvAggXRAr/DXyw5vQjAmQT/xN/S0AeRBFEd1w6IMkaFBTYoja4hbYNngO3FWqggAgDUZAmCNM/rFBBKi0JbeJ/dsEF0QBqIKotgi/HdUZqN1ruy9YjWOKn" ascii /* score: '11.00'*/
      $s10 = "XXsdOMEan1pcN8FCihtp2dlYUked2IkQGsweBz0BarjTF0ln/vJfeZXl7XXd53P5vldpV15l+2XrV9GulOAN8NGiZhVj/Hac8E5GkufbiyO6shOI4Bco1jTcZ90ESyHN" ascii /* score: '11.00'*/
      $s11 = "Jku0bHAPm+y9F60IX8ICR7btqMjOvJCt9cEy0SX1orNctJZfa5tCtqOeFzf2ju26q3IiE+6o6bo5eBXdYxvc+y+fKQqdsTN9lFw8Xz1Xcu1Dn8oPEdE2NsTmjWyMX4v7" ascii /* score: '11.00'*/
      $s12 = "          <br><a href='https://localbitcoins.com/buy_bitcoins'>https://localbitcoins.com/buy_bitcoins</a>" fullword ascii /* score: '11.00'*/
      $s13 = "2Wwg/Xvm5+e/W6lU5oGBpjK1QR6sC/8SiAOMj49jmhFCoSGiUXHVsCSZTLZjVV3XaTSa/OIX58nnF8hmLzI/P8+lS5e693fy+fzL58+f/9HJkyfP2La9TOx0XVdvv/32" ascii /* score: '11.00'*/
      $s14 = "wHEsbLuGaWpkMhkAIpHIndPT08/X6/VNU9WbSvAdd9zx74DfAxgdHWV8fILR0b3EYjrh8NVDoXA4TDKZRAiBqqrtsmA+X+LVVy8wO5shl5snn59maekS1Wq+TW6lUqBW" ascii /* score: '11.00'*/
      $s15 = "jqZpaJoGgOM4OI6DbdvU6/VrHeZnQoj/snv37m88/vjjXm/PYDB4WxJ86NChh4QQnwHe2b1cCEE0GiWRSBAOhwmHwyiK0rXen5eyw5XnedRqNSqVCoVCgXK5jJTy8kO+" ascii /* score: '11.00'*/
      $s16 = "6/8/NukGs9fEhYxLvlQnGW7pdGeBnhrBNaHrGvYIPX4EUIIiWG6LB0Fua77htW3x0anV1YOlhKMXGx3nSr3RP4fNmpCdiKQH6P24aEX4Q01Fi6hlvy3SRBe5oovQ7m0D" ascii /* score: '11.00'*/
      $s17 = "zAyLi+2x697k5ORTzz///NPFYrGMT+Zs63ceuABMAZOt+QvAuWKxeOnEiROvJxKJZiKR+FUhhFKtVlvxrEBVI7iuZHh4CE3TcBwHXdcpl8vtuLl7UlWJ61rU60vYdpNy" ascii /* score: '11.00'*/
      $s18 = "W6LRKFEup6nVCjQaTQqFJouLBSIRg0gkhGEYbe86sMtXI1lVBSBQ1SjNZgnbblKtVlFVNToyMmKdPn36J0C1D5fwLbFpBB88eHBMUZSvA4aqqm3VHI3GSSSu3q1AcsFX" ascii /* score: '11.00'*/
      $s19 = "RhkZuZmhoQlSKYvx8Qi6rly7sQ1A1xWGhgwURUGICLoeRtM8otEIS0tLeJ6Hoig31uv13z5w4MBfHTt27Jox12ZgyxH86KOPGpqmPQu8D3xy9+3bRyIxzOjoXiKRIXbs" ascii /* score: '11.00'*/
      $s20 = "zrw+1iblxSOvsZhdWvd5/OToKS7NL/jteXbLppcGLMHBFe0Nei/B3mWd7ie5ElCG2gS/fOz0xrovJUdePd2RYnMX2OWOWen3FNhg7y27umr0Lxft9VEtt9fr+IUAB8f1" ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 40KB and
      8 of them
}


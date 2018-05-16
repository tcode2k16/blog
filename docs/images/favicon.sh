magick avatar.png \( +clone -threshold 101% -fill white -draw 'circle %[fx:int(w/2)],%[fx:int(h/2)] %[fx:int(w/2)],%[fx:80+int(h/2)]' \) -channel-fx '| gray=>alpha' avatar_circle.png
convert -trim -background transparent "avatar_circle.png" -define icon:auto-resize=16,24,32,48,64,72,96,128,256 "favicon.ico"

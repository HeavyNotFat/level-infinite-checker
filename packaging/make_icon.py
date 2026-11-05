from PIL import Image, ImageDraw

NAVY = (16, 24, 40, 255)
BLUE = (31, 94, 255, 255)
WHITE = (255, 255, 255, 255)
LIGHT = (203, 213, 225, 255)

size = 256
img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle([8, 8, 248, 248], radius=48, fill=NAVY)
# shield
points = [(128, 34), (202, 66), (195, 154), (128, 220), (61, 154), (54, 66)]
d.polygon(points, fill=BLUE)
# inner shield
inner = [(128, 54), (180, 78), (175, 146), (128, 198), (81, 146), (76, 78)]
d.polygon(inner, fill=(20, 35, 75, 255))
# check mark
d.line([(92, 128), (118, 155), (169, 96)], fill=WHITE, width=18, joint="curve")
# small status dot
d.ellipse([184, 184, 224, 224], fill=(34, 197, 94, 255))
d.ellipse([194, 194, 214, 214], fill=WHITE)
img.save("assets/viruschecker.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("icon written")

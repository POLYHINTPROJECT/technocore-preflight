# Social preview asset

`social-preview.svg` is the **master** for the repository's social media
preview image (the card shown when the repo link is shared on social
platforms / chat apps).

GitHub requires a raster upload (PNG/JPG/GIF, <= 1 MB) at **1280 x 640**:

1. Render the SVG at its native 1280x640 size and export as PNG
   (any of: Inkscape `inkscape social-preview.svg -o social-preview.png`,
   `rsvg-convert`, Figma, or a browser screenshot at exact size).
2. Check the file is under 1 MB.
3. Upload manually: repository **Settings -> General -> Social preview ->
   Edit -> Upload a new image**. (This step is intentionally not automated.)

Design rules baked into the master: solid near-black background (no
transparency issues across platforms), semantic green used ONLY for the PASS
verdict, no gradients, no DID on the card, real protocol output as the visual.

The two `verdict-strip-{light,dark}.svg` files beside this folder are the
theme-adaptive inline strip used in README.md above the fold via `<picture>`.

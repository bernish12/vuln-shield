from pptx import Presentation
import os

try:
    ppt_path = "C:\\Users\\P52\\Desktop\\VulnShield_Presentation.pptx"
    
    if not os.path.exists(ppt_path):
        print(f"ERROR: File not found at {ppt_path}")
        exit(1)

    prs = Presentation(ppt_path)
    
    # Get the slides collection and the count
    slides = prs.slides._sldIdLst
    num_slides = len(slides)
    
    if num_slides > 0:
        # Delete the last slide (which is the one we just added)
        last_slide_id = slides[num_slides - 1]
        slides.remove(last_slide_id)
        
        prs.save(ppt_path)
        print(f"SUCCESS: Deleted the last slide from {ppt_path}")
    else:
        print("ERROR: No slides to delete.")

except Exception as e:
    print(f"ERROR: {str(e)}")

from pathlib import Path

from reportlab.lib.colors import Color, HexColor, white
from reportlab.lib.pagesizes import letter
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = PROJECT_ROOT / "output" / "pdf" / "practical-ai-module-1-workbook.pdf"
WIDTH, HEIGHT = letter
MARGIN = 46

INK = HexColor("#111827")
MUTED = HexColor("#4B5563")
PAPER = HexColor("#F7FAFC")
PANEL = HexColor("#EEF4F8")
DARK = HexColor("#07101C")
CYAN = HexColor("#00D9F5")
PURPLE = HexColor("#8B5CF6")
GREEN = HexColor("#10B981")
AMBER = HexColor("#D97706")
BORDER = HexColor("#C9D7E3")


def wrap_text(text, font, size, max_width):
    words = text.split()
    lines = []
    current = ""
    for word in words:
        candidate = word if not current else current + " " + word
        if stringWidth(candidate, font, size) <= max_width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def draw_wrapped(pdf, text, x, y, max_width, font="Helvetica", size=10, leading=14, color=INK):
    pdf.setFillColor(color)
    pdf.setFont(font, size)
    for line in wrap_text(text, font, size, max_width):
        pdf.drawString(x, y, line)
        y -= leading
    return y


def page_header(pdf, week, title, subtitle):
    pdf.setFillColor(PAPER)
    pdf.rect(0, 0, WIDTH, HEIGHT, fill=1, stroke=0)
    pdf.setFillColor(DARK)
    pdf.rect(0, HEIGHT - 106, WIDTH, 106, fill=1, stroke=0)
    pdf.setFillColor(CYAN)
    pdf.rect(0, HEIGHT - 106, 8, 106, fill=1, stroke=0)
    pdf.setFont("Helvetica-Bold", 9)
    pdf.setFillColor(CYAN)
    pdf.drawString(MARGIN, HEIGHT - 34, "DIGITAL LITERACY & AWARENESS | " + week.upper())
    pdf.setFont("Helvetica-Bold", 23)
    pdf.setFillColor(white)
    pdf.drawString(MARGIN, HEIGHT - 65, title)
    pdf.setFont("Helvetica", 9.5)
    pdf.setFillColor(HexColor("#C7D5E8"))
    pdf.drawString(MARGIN, HEIGHT - 86, subtitle)


def footer(pdf, page_number):
    pdf.setStrokeColor(BORDER)
    pdf.line(MARGIN, 35, WIDTH - MARGIN, 35)
    pdf.setFont("Helvetica", 8)
    pdf.setFillColor(MUTED)
    pdf.drawString(MARGIN, 22, "Practical AI for Everyday Life | Module 1 Workbook")
    pdf.drawRightString(WIDTH - MARGIN, 22, "Page " + str(page_number))


def section_title(pdf, y, title, label=None, accent=PURPLE):
    if label:
        pdf.setFont("Helvetica-Bold", 8)
        pdf.setFillColor(accent)
        pdf.drawString(MARGIN, y, label.upper())
        y -= 18
    pdf.setFont("Helvetica-Bold", 15)
    pdf.setFillColor(INK)
    pdf.drawString(MARGIN, y, title)
    return y - 20


def note_box(pdf, y, title, text, height=58, accent=CYAN):
    pdf.setFillColor(PANEL)
    pdf.setStrokeColor(BORDER)
    pdf.roundRect(MARGIN, y - height, WIDTH - (2 * MARGIN), height, 8, fill=1, stroke=1)
    pdf.setFillColor(accent)
    pdf.rect(MARGIN, y - height, 5, height, fill=1, stroke=0)
    pdf.setFont("Helvetica-Bold", 9)
    pdf.setFillColor(INK)
    pdf.drawString(MARGIN + 16, y - 20, title)
    draw_wrapped(pdf, text, MARGIN + 16, y - 36, WIDTH - (2 * MARGIN) - 32, size=8.5, leading=11, color=MUTED)
    return y - height - 12


def writing_box(pdf, y, title, prompt, lines=4, accent=PURPLE):
    box_height = 56 + (lines * 18)
    pdf.setFillColor(white)
    pdf.setStrokeColor(BORDER)
    pdf.roundRect(MARGIN, y - box_height, WIDTH - (2 * MARGIN), box_height, 8, fill=1, stroke=1)
    pdf.setFillColor(accent)
    pdf.rect(MARGIN, y - 34, WIDTH - (2 * MARGIN), 34, fill=1, stroke=0)
    pdf.setFont("Helvetica-Bold", 10)
    pdf.setFillColor(white)
    pdf.drawString(MARGIN + 14, y - 22, title)
    prompt_y = draw_wrapped(pdf, prompt, MARGIN + 14, y - 49, WIDTH - (2 * MARGIN) - 28, size=8.5, leading=11, color=MUTED)
    line_y = min(prompt_y - 10, y - 72)
    pdf.setStrokeColor(HexColor("#B8C7D4"))
    for _ in range(lines):
        pdf.line(MARGIN + 14, line_y, WIDTH - MARGIN - 14, line_y)
        line_y -= 18
    return y - box_height - 12


def checklist(pdf, y, items, columns=1):
    usable = WIDTH - (2 * MARGIN)
    column_width = usable / columns
    rows = (len(items) + columns - 1) // columns
    for index, item in enumerate(items):
        column = index // rows
        row = index % rows
        x = MARGIN + (column * column_width)
        row_y = y - (row * 27)
        pdf.setStrokeColor(PURPLE)
        pdf.rect(x, row_y - 11, 11, 11, fill=0, stroke=1)
        draw_wrapped(pdf, item, x + 18, row_y - 2, column_width - 24, size=8.8, leading=11, color=INK)
    return y - (rows * 27) - 8


def build_workbook():
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    pdf = canvas.Canvas(str(OUTPUT_PATH), pagesize=letter, pageCompression=1)
    pdf.setTitle("Practical AI for Everyday Life - Module 1 Workbook")
    pdf.setAuthor("GT Bailey")
    pdf.setSubject("Printable activities for the August 2026 Digital Literacy & Awareness course")

    # Page 1 - Cover
    pdf.setFillColor(DARK)
    pdf.rect(0, 0, WIDTH, HEIGHT, fill=1, stroke=0)
    pdf.setFillColor(Color(0, 0.85, 0.96, alpha=0.10))
    pdf.circle(WIDTH - 95, HEIGHT - 135, 155, fill=1, stroke=0)
    pdf.setFillColor(Color(0.55, 0.36, 0.96, alpha=0.12))
    pdf.circle(95, 135, 180, fill=1, stroke=0)
    pdf.setFillColor(CYAN)
    pdf.rect(MARGIN, HEIGHT - 90, 190, 4, fill=1, stroke=0)
    pdf.setFont("Helvetica-Bold", 10)
    pdf.drawString(MARGIN, HEIGHT - 68, "DIGITAL LITERACY & AWARENESS")
    pdf.setFont("Helvetica-Bold", 40)
    pdf.setFillColor(white)
    pdf.drawString(MARGIN, HEIGHT - 168, "PRACTICAL AI")
    pdf.drawString(MARGIN, HEIGHT - 216, "FOR EVERYDAY LIFE")
    pdf.setFont("Helvetica-Bold", 21)
    pdf.setFillColor(PURPLE)
    pdf.drawString(MARGIN, HEIGHT - 264, "MODULE 1 WORKBOOK")
    pdf.setFont("Helvetica", 13)
    pdf.setFillColor(HexColor("#C7D5E8"))
    pdf.drawString(MARGIN, HEIGHT - 298, "Understand AI | August 2026 | Lessons 1-12")
    pdf.setFillColor(Color(1, 1, 1, alpha=0.05))
    pdf.setStrokeColor(Color(0, 0.85, 0.96, alpha=0.35))
    pdf.roundRect(MARGIN, 186, WIDTH - (2 * MARGIN), 190, 14, fill=1, stroke=1)
    pdf.setFont("Helvetica-Bold", 12)
    pdf.setFillColor(CYAN)
    pdf.drawString(MARGIN + 20, 344, "YOUR WORKBOOK")
    pdf.setFont("Helvetica", 10)
    pdf.setFillColor(white)
    pdf.drawString(MARGIN + 20, 315, "Name: _________________________________________________")
    pdf.drawString(MARGIN + 20, 282, "Start date: _____________________________________________")
    pdf.drawString(MARGIN + 20, 249, "One skill I want to build: _________________________________")
    pdf.drawString(MARGIN + 20, 216, "_______________________________________________________")
    pdf.setFillColor(HexColor("#A9BED5"))
    pdf.setFont("Helvetica", 9)
    pdf.drawString(MARGIN, 82, "Start small. Ask clearly. Review carefully. Verify what matters.")
    pdf.setFillColor(CYAN)
    pdf.rect(MARGIN, 60, WIDTH - (2 * MARGIN), 2, fill=1, stroke=0)
    pdf.setFillColor(white)
    pdf.setFont("Helvetica-Bold", 10)
    pdf.drawString(MARGIN, 40, "GT BAILEY | CYBERSECURITY & DIGITAL LITERACY CREATOR")
    pdf.showPage()

    # Page 2 - Week 1
    page_header(pdf, "Week 1", "Meet AI in Everyday Life", "Lessons 1-3 | Recognition, awareness, and one safe first task")
    y = HEIGHT - 136
    y = note_box(pdf, y, "Plain-language reminder", "AI is a digital tool that finds patterns and produces likely responses. It can be helpful without being human, magical, or always correct.")
    y = writing_box(pdf, y, "1. Explain AI", "Write a one- or two-sentence explanation for a friend who has never used AI.", lines=3, accent=CYAN)
    y = writing_box(pdf, y, "2. AI Around Me Inventory", "List three apps or services, the feature that may use AI, and how that feature helps or influences you.", lines=5, accent=PURPLE)
    y = writing_box(pdf, y, "3. Choose a First Task", "Name one familiar, low-risk task. Explain how you will review the result before using it.", lines=4, accent=GREEN)
    footer(pdf, 2)
    pdf.showPage()

    # Page 3 - Week 2
    page_header(pdf, "Week 2", "Benefits, Limits, and Safe Use", "Lessons 4-6 | Privacy, verification, and human judgment")
    y = HEIGHT - 138
    y = section_title(pdf, y, "Benefits or limitations?", "Quick classification", CYAN)
    y = checklist(pdf, y, [
        "Turns rough notes into a checklist - benefit or limitation?",
        "May invent a believable source - benefit or limitation?",
        "Can explain a topic more simply - benefit or limitation?",
        "May miss context or reflect bias - benefit or limitation?"
    ], columns=1)
    y -= 8
    y = writing_box(pdf, y, "Safe, Edit First, or Do Not Share", "Classify: a general grocery list; a budget with account numbers; a password-strength request containing the password; confidential client records.", lines=5, accent=PURPLE)
    y = writing_box(pdf, y, "When should you slow down?", "Name one AI task you would use normally and one involving health, rights, money, safety, eligibility, or private data that requires an official source or qualified person.", lines=4, accent=AMBER)
    footer(pdf, 3)
    pdf.showPage()

    # Page 4 - Week 3
    page_header(pdf, "Week 3", "Build a Better Prompt", "Lessons 7-9 | Patterns, changing responses, and clear instructions")
    y = HEIGHT - 138
    y = note_box(pdf, y, "Prompt formula", "Task + Context + Format + Limits reduces guesswork. It improves usefulness, but important claims still need verification.", height=62)
    y = writing_box(pdf, y, "TASK", "What exactly should the AI do? Start with an action such as summarize, rewrite, compare, plan, or explain.", lines=3, accent=CYAN)
    y = writing_box(pdf, y, "CONTEXT", "What background, audience, or purpose does it need? Use placeholders instead of private details.", lines=3, accent=PURPLE)
    y = writing_box(pdf, y, "FORMAT", "How should the answer be presented: bullets, email, checklist, table, or steps?", lines=2, accent=CYAN)
    y = writing_box(pdf, y, "LIMITS", "Set tone, length, must-include details, exclusions, and what the AI should label rather than invent.", lines=2, accent=PURPLE)
    footer(pdf, 4)
    pdf.showPage()

    # Page 5 - Week 4
    page_header(pdf, "Week 4", "Notice AI and Build One Habit", "Lessons 10-12 | Everyday tools, realistic benefits, and routine")
    y = HEIGHT - 138
    y = writing_box(pdf, y, "Audit One Familiar App", "Record the app, likely AI feature, benefit, data it may use, and one privacy or personalization setting to review.", lines=5, accent=CYAN)
    y = section_title(pdf, y, "Which benefit would help most?", "Choose one", PURPLE)
    y = checklist(pdf, y, ["Save time", "Improve writing", "Stay organized", "Generate ideas", "Learn more clearly"], columns=2)
    y -= 8
    y = writing_box(pdf, y, "Create a One-Week Habit", "Name the task, your starter prompt, when you will use it, and the facts or details you will double-check.", lines=6, accent=GREEN)
    y = note_box(pdf, y, "Keep yourself in control", "A useful habit should save time without weakening understanding. Change or stop the routine if it creates confusion or extra work.", height=62, accent=AMBER)
    footer(pdf, 5)
    pdf.showPage()

    # Page 6 - Review
    page_header(pdf, "Module 1 Review", "Your Practical AI Action Plan", "Complete after Lessons 1-12")
    y = HEIGHT - 138
    y = section_title(pdf, y, "Completion check", "Twelve lessons", CYAN)
    y = checklist(pdf, y, [
        "1. What Is AI?", "2. Where AI Already Appears", "3. First Easy Uses",
        "4. Benefits vs. Limitations", "5. Using AI Safely", "6. When to Slow Down",
        "7. How AI Learns", "8. Why Responses Change", "9. Better Prompts",
        "10. AI in Everyday Tools", "11. Benefits of AI", "12. First AI Habit"
    ], columns=2)
    y -= 8
    y = writing_box(pdf, y, "My Reusable Prompt", "Write one prompt you want to keep using. Include task, context, format, and limits.", lines=5, accent=PURPLE)
    y = writing_box(pdf, y, "My Review Rules", "What will you always check before using, sharing, or acting on an AI response?", lines=4, accent=AMBER)
    y = writing_box(pdf, y, "My Next Small Step", "Name one low-risk action you will take during the next seven days.", lines=2, accent=GREEN)
    footer(pdf, 6)
    pdf.save()
    print(OUTPUT_PATH)


if __name__ == "__main__":
    build_workbook()

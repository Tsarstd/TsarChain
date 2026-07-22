# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import base64

from io import BytesIO
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
from typing import Dict, Any, Optional, Tuple, List

from tsarchain.utils import config as CFG
import tsarcore_native as native_core # Rust

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.web.build_history_book")


class HistoryBookGenerator:
    _template_cache = {}
    _font_cache = {}


    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.template_path = "src/web/Backend/src/template/history_book_template_body.jpg"
        self.header_p2wpkh = "src/web/Backend/src/template/history_book_head_p2wpkh.jpg"
        self.header_p2wsh  = "src/web/Backend/src/template/history_book_head_p2wsh.jpg"
        self.font_template = "src/web/Backend/src/template/font_template.ttf"
        
        os.makedirs(self.output_dir, exist_ok=True)
        self._ensure_template_cache()
        self._ensure_font_cache()
        
        self.title_font = self.__class__._font_cache['title_28']
        self.normal_font = self.__class__._font_cache['normal_20']
        self.small_font = self.__class__._font_cache['small_15']
        self.monospace_font = self.__class__._font_cache['monospace_21']


    def generate_history_book(self, data: Dict[str, Any]) -> Tuple[bool, str, Optional[bytes]]:
        try:
            if not data or 'address' not in data:
                return False, "Invalid history data", None
                
            address = data.get('address', 'Unknown')
            width = 800
            
            pages = []
            
            # 1. Cover
            pages.append(self._draw_cover_page(data, width))
            
            # 2. History pages
            history = data.get('history', [])
            if history:
                paginated_history = native_core.paginate_history(history, 8)
                for i, page_txs in enumerate(paginated_history):
                    pages.append(self._draw_history_page(i, len(paginated_history), page_txs, width))
            
            # 3. Footer
            pages.append(self._draw_footer_page(data, width))
            
            # Save to PDF
            buffer = BytesIO()
            pages[0].save(
                buffer,
                format='PDF',
                resolution=300.0,
                save_all=True,
                append_images=pages[1:]
            )
            
            pdf_bytes = buffer.getvalue()
            output_filename = f"history_{address}.pdf"
            output_path = os.path.join(self.output_dir, output_filename)
            
            with open(output_path, 'wb') as f:
                f.write(pdf_bytes)
                
            return True, output_path, pdf_bytes
            
        except Exception as e:
            log.exception("Failed to generate history book")
            return False, f"Error: {str(e)}", None


    def generate_history_book_base64(self, data: Dict[str, Any]) -> Dict[str, Any]:
        success, message, pdf_bytes = self.generate_history_book(data)
        
        if success and pdf_bytes:
            base64_pdf = base64.b64encode(pdf_bytes).decode('utf-8')
            return {
                "status": "success",
                "message": "History Book generated successfully",
                "data_url": f"data:application/pdf;base64,{base64_pdf}",
                "filename": f"history_{data.get('address')}.pdf",
                "size_bytes": len(pdf_bytes)
            }
        else:
            return {
                "status": "error",
                "message": message or "Failed to generate history book"
            }


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    @classmethod
    def _ensure_template_cache(cls):
        template_paths = {
            'body': "src/web/Backend/src/template/history_book_template_body.jpg",
            'p2wpkh': "src/web/Backend/src/template/history_book_head_p2wpkh.jpg",
            'p2wsh': "src/web/Backend/src/template/history_book_head_p2wsh.jpg",
        }
        for key, path in template_paths.items():
            if key not in cls._template_cache:
                if os.path.exists(path):
                    try:
                        img = Image.open(path)
                        if img.mode != 'RGB':
                            img = img.convert('RGB')
                        cls._template_cache[key] = img
                    except Exception as e:
                        log.warning(f"Failed to load template {path}: {e}")
                        cls._template_cache[key] = Image.new('RGB', (800, 1200), color=(255, 255, 255))
                else:
                    cls._template_cache[key] = Image.new('RGB', (800, 1200), color=(255, 255, 255))


    @classmethod
    def _ensure_font_cache(cls):
        font_template = "src/web/Backend/src/template/font_template.ttf"
        font_sizes = {
            'title': 28,
            'normal': 20,
            'small': 15,
            'monospace': 21
        }
        for name, size in font_sizes.items():
            key = f"{name}_{size}"
            if key not in cls._font_cache:
                try:
                    cls._font_cache[key] = ImageFont.truetype(font_template, size)
                except Exception as e:
                    log.warning(f"Failed to load font {font_template}: {e}")
                    cls._font_cache[key] = ImageFont.load_default()

     
    def _create_blank_page(self, page_type: str = 'body') -> Image.Image:
        if isinstance(self.__class__._template_cache, dict) and page_type in self.__class__._template_cache:
            return self.__class__._template_cache[page_type].copy()
        elif isinstance(self.__class__._template_cache, dict) and 'body' in self.__class__._template_cache:
            return self.__class__._template_cache['body'].copy()
        return Image.new('RGB', (800, 1200), color=(255, 255, 255))


    def _draw_amount_with_style(
        self,
        draw: ImageDraw.ImageDraw,
        x: int,
        y: int,
        amount: Any,
        font: ImageFont.FreeTypeFont, 
        normal_color=(3, 95, 166),
        decimal_color=(68, 134, 183),
        unit_color=(62, 62, 62)
    ) -> int:

        integer_part, decimal_part, unit = native_core.split_amount_parts(str(amount), CFG.TSAR)
        draw.text((x, y), integer_part, font=font, fill=normal_color)
        x += draw.textlength(integer_part, font=font)
        draw.text((x, y), ',', font=font, fill=normal_color)
        x += draw.textlength(',', font=font)
        original_x = x
        offset = 1

        for i in range(3):
            offset_x = original_x + (i * offset / 3)
            color_shade = (min(255, decimal_color[0] + i * 20), min(255, decimal_color[1] + i * 20), min(255, decimal_color[2] + i * 20))
            draw.text((offset_x, y), decimal_part, font=font, fill=color_shade)

        draw.text((original_x + offset, y), decimal_part, font=font, fill=decimal_color)
        x = original_x + draw.textlength(decimal_part, font=font) + offset
        draw.text((x + 5, y), unit, font=font, fill=unit_color)
        total_text = f"{integer_part},{decimal_part}{unit}"
        return draw.textlength(total_text, font=font) + offset


    def _draw_table_row(
        self,
        draw,
        y_position,
        label,
        value,
        font_label,
        font_value,
        page_width=800,
        is_amount=False,
        amount_value=None
    ):

        row_data = native_core.draw_table_row_data(y_position, label, value, is_amount, str(amount_value) if amount_value is not None else None, page_width)
        draw.text((50, row_data.y_position), row_data.label, font=font_label, fill=row_data.label_color)

        if is_amount and row_data.amount_value:
            value_width = draw.textlength(row_data.value, font=font_value)
            self._draw_amount_with_style(draw, page_width - 50 - value_width, row_data.y_position, row_data.amount_value, font_value)
        else:
            value_width = draw.textlength(row_data.value, font=font_value)
            draw.text((page_width - 50 - value_width, row_data.y_position), row_data.value, font=font_value, fill=row_data.value_color)

        y_position = row_data.y_position + 20
        # draw.line([(50, y_position), (page_width - 50, y_position)], fill=row_data.line_color, width=1)
        return y_position + 10


    def _draw_address_grid(self, draw: ImageDraw.ImageDraw, address: str, x_start: int, y_start: int) -> int:
        grid_data = native_core.draw_address_grid_data(
            address, float(x_start), float(y_start), 18.0, 25.0, 15.0
        )
        
        for char, x, y, color in grid_data.char_positions:
            draw.text((x, y), char, font=self.monospace_font, fill=color)
            
        y_next = y_start + grid_data.total_height + 5.0
        
        if grid_data.label_type and grid_data.address_type:
            badge_text = f"{grid_data.label_type} ({grid_data.address_type})"
            badge_width = draw.textlength(badge_text, font=self.small_font)
            grid_width = 4 * 5 * 18.0 + 3 * 15.0  # 405.0 px
            badge_x = x_start + (grid_width - badge_width) / 2.0
            draw.text((badge_x, y_next), badge_text, font=self.small_font, fill=(240, 240, 240))
            y_next += 20.0
            
        return int(y_next + 10.0)


    def _draw_cover_page(self, data: Dict[str, Any], width: int) -> Image.Image:
        address = data.get('address', '')
        if len(address) == 64:
            page_type = 'p2wsh'
        elif len(address) == 44:
            page_type = 'p2wpkh'
        else:
            page_type = 'body'

        img = self._create_blank_page(page_type=page_type)
        draw = ImageDraw.Draw(img)
        
        title = "HISTORY TRANSACTIONS BOOK"
        title_width = draw.textlength(title, font=self.title_font)
        draw.text(((width - title_width) // 2, 50), title, font=self.title_font, fill=(62, 62, 62))
        
        timestamp_text = f"Generated: {datetime.now().strftime('%B %d, %Y - %H:%M:%S')}"
        timestamp_width = draw.textlength(timestamp_text, font=self.small_font)
        draw.text(((width - timestamp_width) // 2, 83), timestamp_text, font=self.small_font, fill=(3, 95, 166))
        
        line_text = "- " * 25
        line_width = draw.textlength(line_text, font=self.title_font)
        draw.text(((width - line_width) // 2, 85), line_text, font=self.title_font, fill=(151, 151, 151))
        draw.text(((width - line_width) // 2, 28), line_text, font=self.title_font, fill=(151, 151, 151))

        address = data.get('address', 'Unknown')
        self._draw_address_grid(draw, address, 197, 170)
        
        y_pos = 370
        balance = data.get('balance', 0)
        y_pos = self._draw_table_row(draw, y_pos, "Balance :", "", self.small_font, self.small_font, width, is_amount=True, amount_value=balance)
        
        spendable = data.get('spendable', 0)
        y_pos = self._draw_table_row(draw, y_pos, "Spendable :", "", self.small_font, self.small_font, width, is_amount=True, amount_value=spendable)
        
        immature = data.get('immature', 0)
        y_pos = self._draw_table_row(draw, y_pos, "Immature :", "", self.small_font, self.small_font, width, is_amount=True, amount_value=immature)
        
        outgoing = data.get('outgoing', 0)
        y_pos = self._draw_table_row(draw, y_pos, "Total Outgoing :", "", self.small_font, self.small_font, width, is_amount=True, amount_value=outgoing)
        
        incoming = data.get('incoming', 0)
        y_pos = self._draw_table_row(draw, y_pos, "Total Incoming :", "", self.small_font, self.small_font, width, is_amount=True, amount_value=incoming)
        
        utxo = data.get('utxo_count', 0)
        y_pos = self._draw_table_row(draw, y_pos, "UTXO Count :", str(utxo), self.small_font, self.small_font, width)
        
        total_tx = data.get('total_txs', 0)
        y_pos = self._draw_table_row(draw, y_pos, "Total Transactions :", str(total_tx), self.small_font, self.small_font, width)
        
        return img


    def _draw_history_page(self, page_index: int, total_pages: int, transactions: List[Dict[str, Any]], width: int) -> Image.Image:
        img = self._create_blank_page()
        draw = ImageDraw.Draw(img)
        
        title = f"PAGE {page_index + 1}/{total_pages}"
        title_width = draw.textlength(title, font=self.title_font)
        draw.text(((width - title_width) // 2, 50), title, font=self.title_font, fill=(62, 62, 62))
        
        line_text = "- " * 25
        line_width = draw.textlength(line_text, font=self.title_font)
        draw.text(((width - line_width) // 2, 85), line_text, font=self.title_font, fill=(151, 151, 151))
        
        y_pos = 130
        for tx in transactions:
            txid = tx.get('txid', '')
            direction = native_core.format_history_direction(tx.get('direction', ''))
            amount = tx.get('amount', 0)
            status = tx.get('status', 'unconfirmed')
            timestamp = tx.get('timestamp', 0)
            
            # Simple UI for each transaction
            dt = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "Pending"
            
            color = (3, 166, 95) if direction == 'Incoming' else (232, 114, 35) # Green for in, Orange for out
            color_status = (92, 137, 81) if status == 'confirmed' else (179, 83, 83)
            
            draw.text((50, y_pos), dt, font=self.small_font, fill=(62, 62, 62))
            draw.text((250, y_pos), direction, font=self.small_font, fill=color)
            
            self._draw_amount_with_style(draw, 400, y_pos, amount, self.small_font)
            y_pos += 25
            
            draw.text((50, y_pos), f"{txid}", font=self.small_font, fill=(100, 100, 100))
            y_pos += 25
            
            if direction == 'Incoming' and tx.get('from'):
                draw.text((50, y_pos), f"From: {tx.get('from')}", font=self.small_font, fill=(62, 62, 62))
                y_pos += 25
            elif direction == 'Outgoing' and tx.get('to'):
                draw.text((50, y_pos), f"To: {tx.get('to')}", font=self.small_font, fill=(62, 62, 62))
                y_pos += 25
                
            draw.text((50, y_pos), f"{status}", font=self.small_font, fill=color_status)
            
            height = tx.get('height')
            confirmations = tx.get('confirmations', 0)
            if height is None or status == 'unconfirmed':
                height_str = "On Mempool"
                confirms_str = ""
            else:
                height_str = f"Height: {height}"
                confirms_str = f"Confirms: {confirmations}"
                
            draw.text((250, y_pos), height_str, font=self.small_font, fill=(100, 100, 100))
            if confirms_str:
                draw.text((400, y_pos), confirms_str, font=self.small_font, fill=(100, 100, 100))
            
            y_pos += 25
            draw.line([(50, y_pos), (width - 50, y_pos)], fill=(170, 170, 170), width=3)
            y_pos += 15
            
        return img


    def _draw_footer_page(self, data: Dict[str, Any], width: int) -> Image.Image:
        img = self._create_blank_page()
        draw = ImageDraw.Draw(img)
        
        title = "END OF REPORT"
        title_width = draw.textlength(title, font=self.title_font)
        draw.text(((width - title_width) // 2, 50), title, font=self.title_font, fill=(62, 62, 62))
        
        line_text = "- " * 25
        line_width = draw.textlength(line_text, font=self.title_font)
        draw.text(((width - line_width) // 2, 85), line_text, font=self.title_font, fill=(151, 151, 151))
        
        # QR Code
        qr_prefix = "https://localhost:5173/?search="
        address = data.get('address', '')
        qr_data = qr_prefix + address
        qr_bytes = native_core.generate_qr_code(qr_data)
        qr_img = Image.open(BytesIO(qr_bytes))
        
        qr_size = 200
        qr_img = qr_img.resize((qr_size, qr_size), Image.Resampling.NEAREST)
        qr_x = (width - qr_size) // 2
        qr_y = 150
        
        if qr_img.mode == 'RGBA':
            img.paste(qr_img, (qr_x, qr_y), qr_img)
        else:
            img.paste(qr_img, (qr_x, qr_y))
            
        y_pos = qr_y + qr_size + 40
        
        height = data.get('height', 0)
        draw.text(((width - draw.textlength(f"Block Height: {height}", font=self.normal_font)) // 2, y_pos), f"Block Height: {height}", font=self.normal_font, fill=(62, 62, 62))
        y_pos += 40
        
        footer_text = "Generated by TsarChain Explorer"
        draw.text(((width - draw.textlength(footer_text, font=self.small_font)) // 2, y_pos), footer_text, font=self.small_font, fill=(100, 100, 100))
        
        return img
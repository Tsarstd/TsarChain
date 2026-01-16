# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

import os
import time
import base64

from io import BytesIO
from datetime import datetime
from decimal import Decimal, ROUND_DOWN
from PIL import Image, ImageDraw, ImageFont
from typing import Dict, Any, Optional, Tuple, List

from tsarchain.utils import config as CFG

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.web.build_receipt")

class PaymentReceiptGenerator:
    def __init__(self):
        self.template_path = "src/web/Backend/src/template/receipt_template.jpg"
        self.font_template = "src/web/Backend/src/template/font_template.ttf"
        
        self.confirmed = "src/web/Backend/src/template/confirmed.png"
        self.unconfirmed = "src/web/Backend/src/template/mempool.png"
        
        self.output_dir = "data/web/receipts"
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.title_font = ImageFont.truetype(self.font_template, 28)
        self.normal_font = ImageFont.truetype(self.font_template, 20)
        self.small_font = ImageFont.truetype(self.font_template, 15)
        self.monospace_font = ImageFont.truetype(self.font_template, 21)  # TxID
            
    def _split_amount_parts(self, amount: Any) -> Tuple[str, str, str]:
        
        formatted_amount = self._format_tsar_amount(amount)
        if ',' in formatted_amount:
            parts = formatted_amount.split(',')
            if len(parts) == 2:
                integer_part = parts[0]
                decimal_and_unit = parts[1]
                
                # Pisahkan decimal dan unit
                if ' ' in decimal_and_unit:
                    decimal_parts = decimal_and_unit.split(' ')
                    if len(decimal_parts) >= 2:
                        decimal_part = decimal_parts[0]
                        unit = ' '.join(decimal_parts[1:])
                        
                return integer_part, decimal_part, unit
        
        return formatted_amount, '00000000'
    
    def _format_tsar_amount(self, amount: Any) -> str:
        if amount is None:
            return "0,00000000 TSAR"
        
        if isinstance(amount, str) and not amount.strip():
            return "0,00000000 TSAR"
        
        tsar = Decimal(amount) / Decimal(CFG.TSAR)
        if tsar == 0:
            return "0,00000000 TSAR"
        
        tsar_quantized = tsar.quantize(Decimal('0.00000001'), rounding=ROUND_DOWN)
        tsar_str = format(tsar_quantized, 'f')
        parts = tsar_str.split('.')
        if len(parts) == 1:
            decimal_part = "00000000"
        else:
            decimal_part = parts[1].ljust(8, '0')[:8]
        
        if parts[0]:
            integer_part = int(parts[0])
            formatted_integer = f"{integer_part:,}".replace(',', '.')
        else:
            formatted_integer = "0"
        
        return f"{formatted_integer},{decimal_part} TSAR"
    
    def _draw_amount_with_style(
        self,
        draw: ImageDraw.ImageDraw, 
        x: int, y: int, 
        amount: Any,
        font: ImageFont.FreeTypeFont,
        normal_color: Tuple[int, int, int] = (3, 95, 166),
        decimal_color: Tuple[int, int, int] = (68, 134, 183)
        ) -> int:
        
        integer_part, decimal_part, unit = self._split_amount_parts(amount)
        
        draw.text((x, y), integer_part, font=font, fill=normal_color)
        x += draw.textlength(integer_part, font=font)
        
        draw.text((x, y), ',', font=font, fill=normal_color)
        x += draw.textlength(',', font=font)
        
        decimal_text = decimal_part
        draw.text((x, y), decimal_text, font=font, fill=decimal_color)
        x += draw.textlength(decimal_text, font=font)
        
        draw.text((x + 5, y), unit, font=font, fill=normal_color)
        
        total_text = f"{integer_part},{decimal_part}{unit}"
        return draw.textlength(total_text, font=font)
    
    def _format_datetime(self, timestamp: int) -> str:
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime("%B %d, %Y - %H:%M:%S")
    
    def _pool_address(self, address: str) -> str:
        if not address:
            return ""

        if len(address) == 64:
            return f"{address[:12]}....{address[-22:]}"
        else:
            return address
    
    def _truncate_text(self, text: Any, max_length: int = 64) -> str:
        if text is None:
            text = ""
        else:
            text = str(text)
        
        if len(text) > max_length:
            return text[:max_length-3] + "..."
        return text
    
    def _split_txid_into_grid(self, txid: str) -> List[List[str]]:
        if len(txid) != 64:
            return [[txid]]  # Fallback
        
        chunks = []
        for i in range(0, 60, 5):
            chunks.append(txid[i:i+5])
        
        chunks.append(txid[60:])
        
        # 4x3 + 1 (Tail)
        grid = [
            chunks[0:4],   # Baris 1: 4 kelompok
            chunks[4:8],   # Baris 2: 4 kelompok  
            chunks[8:12],  # Baris 3: 4 kelompok
            [chunks[12]]   # Baris 4: 1 kelompok (4 karakter)
        ]
        
        return grid
    
    def _draw_txid_grid(self, draw: ImageDraw.ImageDraw, txid: str, x_start: int, y_start: int) -> int:
        grid = self._split_txid_into_grid(txid)
        
        highlight_color = (250, 250, 250)
        normal_color = (114, 114, 114)
        
        highlight_positions = [
            (0, 0),  # Baris 1, Kolom 1
            (0, 2),  # Baris 1, Kolom 3
            (1, 1),  # Baris 2, Kolom 2
            (1, 3),  # Baris 2, Kolom 4
            (2, 0),
            (2, 2),
            (3, 0)   # Baris 4, Kolom 1 (karakter terakhir)
        ]
        
        y = y_start
        line_height = 25
        char_width = 18
        group_spacing = 15
        
        for row_idx, row in enumerate(grid):
            x = x_start
            
            if row_idx == 3:
                chunk = row[0]
                for col_idx in range(4):
                    if col_idx < len(chunk):
                        char = chunk[col_idx]
                        char_x = x_start + col_idx * (5 * char_width + group_spacing) + 2 * char_width
                        draw.text((char_x, y), char, font=self.monospace_font, fill=highlight_color)
                        
                y += line_height
                continue 
                
            
            for col_idx, chunk in enumerate(row):
                is_highlighted = (row_idx, col_idx) in highlight_positions
                
                for char_idx, char in enumerate(chunk):
                    char_x = x + char_idx * char_width
                    
                    char_color = highlight_color if is_highlighted else normal_color
                    draw.text((char_x, y), char, font=self.monospace_font, fill=char_color)
                
                if row_idx < 3:
                    x += 5 * char_width + group_spacing
                else:
                    break
                
            y += line_height
            
        return y + 15
    
    def _draw_table_row(self, 
        draw: ImageDraw.ImageDraw, 
        y_position: int, 
        label: str, 
        value: str,
        font_label: ImageFont.FreeTypeFont,
        font_value: ImageFont.FreeTypeFont,
        page_width: int = 800,
        is_amount: bool = False,
        amount_value: Any = None
        ) -> int:
        
        # Label (kiri)
        draw.text((50, y_position), label, font=font_label, fill=(62, 62, 62))
        
        # Value (kanan)
        if is_amount and amount_value is not None:
            integer_part, decimal_part, unit = self._split_amount_parts(amount_value)
            amount_text = f"{integer_part},{decimal_part} {unit}"
            value_width = draw.textlength(amount_text, font=font_value)
            
            # (rata kanan)
            self._draw_amount_with_style(draw, page_width - 50 - value_width, 
                                        y_position, amount_value, font_value)
            
        else:
            value_width = draw.textlength(value, font=font_value)
            draw.text((page_width - 50 - value_width, y_position), 
                    value, font=font_value, fill=(3, 95, 166))
        
        # divider
        y_position += 20
        draw.line([(50, y_position), (page_width - 50, y_position)], 
                fill=(195, 195, 195), width=1)
        
        return y_position + 10
    
    def _add_status_stamp(self, img: Image.Image, status: str) -> Image.Image:
        if status == 'confirmed':
            stamp_path = self.confirmed
        else:
            stamp_path = self.unconfirmed
        
        if os.path.exists(stamp_path):
            stamp = Image.open(stamp_path)
            stamp = stamp.resize((180, 180), Image.Resampling.LANCZOS)
            pos_x = 530
            pos_y = 100

            if stamp.mode == 'RGBA':
                img.paste(stamp, (pos_x, pos_y), stamp)
            else:
                img.paste(stamp, (pos_x, pos_y))
                
        return img
    
    def generate_receipt(self, tx_data: Dict[str, Any]) -> Tuple[bool, str, Optional[bytes]]:
        try:    
            if not tx_data or 'txid' not in tx_data:
                return False, "Invalid transaction data", None
            
            txid = tx_data.get('txid', 'Unknown')
            
            # bg
            if os.path.exists(self.template_path):
                img = Image.open(self.template_path)
                if img.mode != 'RGB':
                    img = img.convert('RGB')
            else:
                # TODO: FORMAL style
                img = Image.new('RGB', (800, 1200), color=(255, 255, 255))
                log.info("Using Formal background")
            
            draw = ImageDraw.Draw(img)
            width, height = img.size
            
            # ============= HEADER =============
            title = "TRANSACTION RECEIPT"
            title_width = draw.textlength(title, font=self.title_font)
            draw.text(((width - title_width) // 2, 50), title, font=self.title_font, fill=(62, 62, 62))
            
            # Timestamp
            timestamp = tx_data.get('timestamp', time.time())
            if timestamp == 0:
                timestamp_text = "This Transaction Still Pending, Please Wait ~37 Seconds"
                status_color = (232, 114, 35)
            else:
                timestamp_text = self._format_datetime(timestamp)
                status_color = (3, 95, 166)

            timestamp_width = draw.textlength(timestamp_text, font=self.small_font)
            draw.text(((width - timestamp_width) // 2, 83), timestamp_text, font=self.small_font, fill=status_color)
            
            #divider
            line_text = "- " * 25
            line_width = draw.textlength(line_text, font=self.title_font)
            
            
            draw.text(((width - line_width) // 2, 85), line_text, font=self.title_font, fill=(151, 151, 151))
            draw.text(((width - line_width) // 2, 28), line_text, font=self.title_font, fill=(151, 151, 151))
            
            y_position = 120
            
            status = tx_data.get('status', 'unconfirmed')
            
            # ============= TXID GRID =============
            y_position = self._draw_txid_grid(draw, txid, 205, 118)
            
            # ============= INFO =============
            status = tx_data.get('status', 'unconfirmed')
            if status == 'unconfirmed':
                block_height_str = "Pending"
                confirmations_str = "Pending"
            else:
                block_height = tx_data.get('height')
                confirmations = tx_data.get('confirmations', 0)
                block_height_str = str(block_height) if block_height is not None else "Unknown"
                confirmations_str = str(confirmations) if confirmations is not None else "0"
            
            y_position = self._draw_table_row(draw, y_position, "Block Height :", 
                                            block_height_str, 
                                            self.small_font, self.small_font, width)
            
            y_position = self._draw_table_row(draw, y_position, "Confirmations :", 
                                            confirmations_str, 
                                            self.small_font, self.small_font, width)
            
            fee = tx_data.get('fee') or 0
            y_position = self._draw_table_row(draw, y_position, "Fee :", 
                                            self._format_tsar_amount(fee), 
                                            self.small_font, self.small_font, width,
                                            is_amount=True, amount_value=fee)
            
            is_coinbase = tx_data.get('is_coinbase', False)
            y_position = self._draw_table_row(draw, y_position, "Coinbase :", 
                                            "Yes" if is_coinbase else "No", 
                                            self.small_font, self.small_font, width)
            
            y_position += 20
            
            # ============= INPUTS =============
            # Sender
            draw.text((50, y_position), "Sender", font=self.normal_font, fill=(232, 114, 35))
            y_position += 40

            inputs = tx_data.get('inputs', [])
            if inputs:
                
                # Group address
                input_groups = {}
                for inp in inputs:
                    addr = inp.get('address')
                    if addr not in input_groups:
                        input_groups[addr] = []
                    input_groups[addr].append(inp)
                
                for addr, utxos in list(input_groups.items())[:3]:  # Max 3 address
                    formatted_addr = self._pool_address(addr)
                    y_position = self._draw_table_row(draw, y_position, 
                                                    f"- {formatted_addr}", 
                                                    f"Used {len(utxos)} UTXOs", 
                                                    self.small_font, self.small_font, width)
                    
                y_position += 10
                
                # +
                end_x = width - 50
                line_length = 15

                draw.line([(end_x - line_length//2, y_position), 
                        (end_x + line_length//2, y_position)], 
                        fill=(150, 150, 150), width=2)

                draw.line([(end_x, y_position - line_length//2), 
                        (end_x, y_position + line_length//2)], 
                        fill=(150, 150, 150), width=2)
                
                y_position += 10
                
                total_input = sum(inp.get('amount', 0) for inp in inputs)
                y_position = self._draw_table_row(draw, y_position, "Total Input :", 
                                                self._format_tsar_amount(total_input), 
                                                self.small_font, self.small_font, width, 
                                                is_amount=True, amount_value=total_input)
                
            else:
                y_position = self._draw_table_row(draw, y_position, "Inputs :", 
                                                "Coinbase Transaction (No Inputs)", 
                                                self.small_font, self.small_font, width)
            
            y_position += 20
            
            # ============= OUTPUTS =============
            draw.text((50, y_position), "Recipient", font=self.normal_font, fill=(232, 114, 35))
            y_position += 40
            
            outputs = tx_data.get('outputs', [])
            if outputs:
                # Filter change & opret
                recipient_outputs = []
                change_outputs = []
                event_outputs = []
                
                input_addresses = set(inp.get('address') for inp in inputs if inp.get('address'))
                
                for out in outputs:
                    addr = out.get('address')
                    # opret
                    if addr is None:
                        event_outputs.append(out)
                    # change
                    elif addr in input_addresses:
                        change_outputs.append(out)
                    else:
                        recipient_outputs.append(out)
                
                # reward mining
                if not inputs:  # Coinbase
                    total_reward = sum(out.get('amount', 0) for out in outputs)
                    y_position = self._draw_table_row(draw, y_position, "Mining Reward :", 
                                                    self._format_tsar_amount(total_reward), 
                                                    self.small_font, self.small_font, width,
                                                    is_amount=True, amount_value=total_reward)
                    
                    # miner
                    recipient_groups = {}
                    for out in outputs:
                        if out.get('address'):
                            addr = out.get('address')
                            if addr not in recipient_groups:
                                recipient_groups[addr] = []
                            recipient_groups[addr].append(out)
                    
                    for addr, outs in list(recipient_groups.items()):
                        y_position = self._draw_table_row(draw, y_position, 
                                                        f"Recipient : {self._truncate_text(addr, 64)}", 
                                                        f"{len(outs)} outputs", 
                                                        self.small_font, self.small_font, width)
                        
                        total_addr = sum(o.get('amount', 0) for o in outs)
                        y_position = self._draw_table_row(draw, y_position, 
                                                        "  Amount :", 
                                                        self._format_tsar_amount(total_addr), 
                                                        self.small_font, self.small_font, width,
                                                        is_amount=True, amount_value=total_addr)
 
                else:

                    if recipient_outputs:
                        recipient_groups = {}
                        for out in recipient_outputs:
                            addr = out.get('address', 'Unknown')
                            if addr not in recipient_groups:
                                recipient_groups[addr] = []
                            recipient_groups[addr].append(out)
                        
                        for addr, outs in list(recipient_groups.items()):
                            total_addr = sum(o.get('amount', 0) for o in outs)
                            formatted_addr = self._pool_address(addr)
                            y_position = self._draw_table_row(draw, y_position, 
                                                            f"- {formatted_addr}", 
                                                            self._format_tsar_amount(total_addr), 
                                                            self.small_font, self.small_font, width,
                                                            is_amount=True, amount_value=total_addr)
                    else:
                        y_position = self._draw_table_row(draw, y_position, "Recipient :", 
                                                        "No external recipients", 
                                                        self.small_font, self.small_font, width)
                    
                    y_position += 10
                    
                    # +
                    end_x = width - 50
                    line_length = 15

                    draw.line([(end_x - line_length//2, y_position), 
                            (end_x + line_length//2, y_position)], 
                            fill=(150, 150, 150), width=2)

                    draw.line([(end_x, y_position - line_length//2), 
                            (end_x, y_position + line_length//2)], 
                            fill=(150, 150, 150), width=2)
                    
                    y_position += 10
                        
                    total_recipient = sum(out.get('amount', 0) for out in recipient_outputs)
                    y_position = self._draw_table_row(draw, y_position, "Total Output :", 
                                                    self._format_tsar_amount(total_recipient), 
                                                    self.small_font, self.small_font, width,
                                                    is_amount=True, amount_value=total_recipient)
                    
                    
                
                # event (POST, COMMENT, PAYOUT)
                if event_outputs:
                    for event_out in event_outputs:
                        event_type = event_out.get('event', 'Unknown Event')
                        y_position = self._draw_table_row(draw, y_position, 
                                                        f"Event :", 
                                                        f"{event_type}", 
                                                        self.small_font, self.small_font, width)
            
            y_position += 30
            
            # ============= SUMMARY =============
            draw.text((50, y_position), "Summary", font=self.normal_font, fill=(232, 114, 35))
            y_position += 40
            
            # total
            total_input_val = sum(inp.get('amount', 0) for inp in inputs)
            
            if not inputs:  # coinbase
                # reward mining
                total_recipient_val = sum(out.get('amount', 0) for out in outputs)
                
                y_position = self._draw_table_row(draw, y_position, "Mining Reward :", 
                                                self._format_tsar_amount(total_recipient_val), 
                                                self.small_font, self.small_font, width,
                                                is_amount=True, amount_value=total_recipient_val)
                
                y_position = self._draw_table_row(draw, y_position, "Fee :", 
                                                self._format_tsar_amount(fee), 
                                                self.small_font, self.small_font, width,
                                                is_amount=True, amount_value=fee)

                y_position += 10
                draw.line([(50, y_position), (width - 50, y_position)], fill=(0, 0, 0), width=2)
                y_position += 20
                
                # Total Reward
                total_reward = total_recipient_val + fee  # fee 0 
                y_position = self._draw_table_row(draw, y_position, "Total Reward :", 
                                                self._format_tsar_amount(total_reward), 
                                                self.small_font, self.small_font, width,
                                                is_amount=True, amount_value=total_reward)
                
            else:
                total_recipient_val = sum(out.get('amount', 0) for out in outputs 
                                         if out.get('address') and 
                                         out.get('address') not in input_addresses)
                
                y_position = self._draw_table_row(draw, y_position, "Total Input :", 
                                                self._format_tsar_amount(total_input_val), 
                                                self.small_font, self.small_font, width,
                                                is_amount=True, amount_value=total_input_val)
                
                y_position = self._draw_table_row(draw, y_position, "Total Output :", 
                                                self._format_tsar_amount(total_recipient_val), 
                                                self.small_font, self.small_font, width,
                                                is_amount=True, amount_value=total_recipient_val)
                
                y_position = self._draw_table_row(draw, y_position, "Fee :", 
                                                self._format_tsar_amount(fee), 
                                                self.small_font, self.small_font, width,
                                                is_amount=True, amount_value=fee)
                
                # garis tebal
                y_position += 10
                draw.line([(740, y_position), (width - 50, y_position)], fill=(150, 150, 150), width=2)
                y_position += 10
                
                # calculate
                change_amount = total_input_val - total_recipient_val - fee
                y_position = self._draw_table_row(draw, y_position, "Change :", 
                                                self._format_tsar_amount(change_amount), 
                                                self.small_font, self.small_font, width,
                                                is_amount=True, amount_value=change_amount)
            
            # ============= FOOTER =============
            footer_y = height - 100
            
            # QR Code placeholder (opsional)
            qr_text = f"txid:{txid}"
            draw.text((width // 2 - 50, footer_y), "Scan for details", 
                     font=self.small_font, fill=(100, 100, 100))
            
            # closing
            footer_text = f"Generated by TsarChain Explorer"
            footer_width = draw.textlength(footer_text, font=self.small_font)
            draw.text(((width - footer_width) // 2, footer_y + 40), footer_text,
                     font=self.small_font, fill=(100, 100, 100))
            
            # ============= SAVE IMAGE =============
            img = self._add_status_stamp(img, status)
            output_filename = f"{txid[:64]}.jpg"
            output_path = os.path.join(self.output_dir, output_filename)
            
            img.save(
                output_path, 
                'JPEG',
                quality=95,
                optimize=True,
                progressive=True,
                subsampling=0
            )
            
            # response
            buffer = BytesIO()
            img.save(
                buffer, 
                format='JPEG',
                quality=95,
                optimize=True,
                progressive=True,
                subsampling=0
            )
            image_bytes = buffer.getvalue()
            return True, output_path, image_bytes
            
        except Exception as e:
            log.error(f"Failed to generate receipt: {e}", exc_info=True)
            return False, f"Error: {str(e)}", None
    
    def generate_receipt_base64(self, tx_data: Dict[str, Any]) -> Dict[str, Any]:
        success, message, image_bytes = self.generate_receipt(tx_data)
        
        if success and image_bytes:
            try:
                base64_image = base64.b64encode(image_bytes).decode('utf-8')
                return {
                    "status": "success",
                    "message": "Receipt generated successfully",
                    "data_url": f"data:image/jpeg;base64,{base64_image}",
                    "filename": f"{tx_data.get('txid')[:64]}.jpg",
                    "size_bytes": len(image_bytes)
                }
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Failed to encode image: {str(e)}"
                }
        else:
            return {
                "status": "error",
                "message": message or "Failed to generate receipt"
            }
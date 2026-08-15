# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import time
import base64
import secrets

from io import BytesIO
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
from typing import Dict, Any, Optional, Tuple

from tsarchain.utils import config as CFG
import tsarcore_native as generated_receipt # Rust

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.web.build_receipt")

_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_TEMPLATE_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, "..", "template"))


class PaymentReceiptGenerator:
    _template_cache = None
    _font_cache = {}
    _stamp_cache = {}
    _rotated_stamp_cache = {}
    _tx_sticker_cache = {}
    
    def __init__(self, path: str):
        self.path          = path
        self.template_path = os.path.join(_TEMPLATE_DIR, "receipt_template.jpg")
        self.font_template = os.path.join(_TEMPLATE_DIR, "font_template.ttf")
        self.qr_prefix     = os.environ.get("EXPLORER_WEB_URL") or "http://localhost:5173/?search="
        
        # Confirmation Stamp
        self.confirmed     = os.path.join(_TEMPLATE_DIR, "confirmed.png")
        self.unconfirmed   = os.path.join(_TEMPLATE_DIR, "mempool.png")
        
        # Transactions Type Sticker
        self.coinbase      = os.path.join(_TEMPLATE_DIR, "coinbase.png")
        self.regular       = os.path.join(_TEMPLATE_DIR, "regular.png")
        self.post          = os.path.join(_TEMPLATE_DIR, "post.png")
        self.comment       = os.path.join(_TEMPLATE_DIR, "comment.png")
        self.payout        = os.path.join(_TEMPLATE_DIR, "payout.png")
        
        os.makedirs(self.path, exist_ok=True)
        self._ensure_template_cache()
        self._ensure_font_cache()
        self._ensure_tx_sticker_cache()

        self.title_font = self.__class__._font_cache['title_28']
        self.normal_font = self.__class__._font_cache['normal_20']
        self.small_font = self.__class__._font_cache['small_15']
        self.monospace_font = self.__class__._font_cache['monospace_21']


    def generate_receipt(self, tx_data: Dict[str, Any]) -> Tuple[bool, str, Optional[bytes]]:
        try:    
            if not tx_data or 'txid' not in tx_data:
                return False, "Invalid transaction data", None
            
            txid = tx_data.get('txid', 'Unknown')
            
            # BG TEMPLATE (800 x 1200 px - 150 ppi)
            if self.__class__._template_cache is not None:
                img = self.__class__._template_cache.copy()
            else:
                img = Image.open(self.template_path)
                if img.mode != 'RGB':
                    img = img.convert('RGB')
            
            draw = ImageDraw.Draw(img)
            width, _ = img.size
            status = tx_data.get('status', 'unconfirmed')
            
            y_position = self._draw_header_and_txid_grid(draw, tx_data, width, txid, status)
            
            inputs = tx_data.get('inputs', [])
            input_addresses = {inp.get('address') for inp in inputs if inp.get('address')}
            
            y_position = self._draw_inputs_section(draw, tx_data, y_position, width)
            
            y_position = self._draw_outputs_section(draw, tx_data, y_position, width, input_addresses)
            
            outputs = tx_data.get('outputs', [])
            summary_y_start, current_y = self._draw_summary_section(draw, tx_data, y_position, inputs, outputs, input_addresses)
            
            output_path, image_bytes = self._draw_stickers_qr_footer(img, draw, tx_data, txid, status, summary_y_start, current_y, width)
            
            return True, output_path, image_bytes
            
        except Exception as e:
            log.exception("Failed to generate receipt")
            return False, f"Error: {str(e)}", None


    def generate_receipt_base64(self, tx_data: Dict[str, Any]) -> Dict[str, Any]:
        success, message, image_bytes = self.generate_receipt(tx_data)
        
        if success and image_bytes:
            base64_image = base64.b64encode(image_bytes).decode('utf-8')
            return {
                "status": "success",
                "message": "Receipt generated successfully",
                "data_url": f"data:image/jpeg;base64,{base64_image}",
                "filename": f"{tx_data.get('txid')[:64]}.jpg",
                "size_bytes": len(image_bytes)
            }
        else:
            return {
                "status": "error",
                "message": message or "Failed to generate receipt"
            }


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    @classmethod
    def _ensure_template_cache(cls):
        if cls._template_cache is None:
            template_path = os.path.join(_TEMPLATE_DIR, "receipt_template.jpg")
            if os.path.exists(template_path):
                img = Image.open(template_path)
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                cls._template_cache = img
            else:
                cls._template_cache = Image.new('RGB', (800, 1200), color=(255, 255, 255))


    @classmethod
    def _ensure_font_cache(cls):
        font_template = os.path.join(_TEMPLATE_DIR, "font_template.ttf")
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


    def _ensure_tx_sticker_cache(self):
        if not self.__class__._tx_sticker_cache:
            sticker_paths = {
                'coinbase': self.coinbase,
                'regular': self.regular,
                'post': self.post,
                'comment': self.comment,
                'payout': self.payout
            }
            
            for tx_type, path in sticker_paths.items():
                if os.path.exists(path):
                    sticker = Image.open(path)
                    sticker = sticker.resize((185, 185), Image.Resampling.LANCZOS)
                    if sticker.mode != 'RGBA':
                        sticker = sticker.convert('RGBA')
                    self.__class__._tx_sticker_cache[tx_type] = sticker
                else:
                    self.__class__._tx_sticker_cache[tx_type] = None


    @classmethod
    def _get_stamp(cls, status: str) -> Optional[Image.Image]:
        cache_key = f"original_{status}"
        if cache_key not in cls._stamp_cache:
            if status == 'confirmed':
                stamp_path = os.path.join(_TEMPLATE_DIR, "confirmed.png")
            else:
                stamp_path = os.path.join(_TEMPLATE_DIR, "mempool.png")
            
            if os.path.exists(stamp_path):
                stamp = Image.open(stamp_path)
                stamp = stamp.resize((180, 180), Image.Resampling.LANCZOS)
                cls._stamp_cache[cache_key] = stamp
            else:
                cls._stamp_cache[cache_key] = None
        
        return cls._stamp_cache.get(cache_key)


    @classmethod
    def _get_rotated_stamp(cls, status: str) -> Optional[Image.Image]:
        rotation_angle = secrets.randbelow(101) - 50
        offset_x = secrets.randbelow(21) - 10
        offset_y = secrets.randbelow(21) - 10
        cache_key = f"rotated_{status}_{rotation_angle}"
        
        if cache_key in cls._rotated_stamp_cache:
            rotated_stamp = cls._rotated_stamp_cache[cache_key]
        else:
            original_stamp = cls._get_stamp(status)
            if not original_stamp:
                return None
            
            if original_stamp.mode != 'RGBA':
                stamp = original_stamp.convert('RGBA')
            else:
                stamp = original_stamp.copy()
            
            rotated_stamp = stamp.rotate(
                rotation_angle,
                expand=True,
                resample=Image.Resampling.BILINEAR
            )

            if len(cls._rotated_stamp_cache) > 200:
                oldest_key = next(iter(cls._rotated_stamp_cache))
                del cls._rotated_stamp_cache[oldest_key]
            
            cls._rotated_stamp_cache[cache_key] = rotated_stamp
        
        # Return a copy with dynamic random offsets attached to prevent thread mutation race conditions
        stamp_copy = rotated_stamp.copy()
        stamp_copy.offset_x = offset_x
        stamp_copy.offset_y = offset_y
        return stamp_copy


    def _get_tx_type_sticker(self, tx_data: Dict[str, Any]) -> Optional[Image.Image]:
        # Skip for mempool/unconfirmed
        if tx_data.get('status') != 'confirmed':
            return None
    
        tx_type = self._determine_tx_type(tx_data)
        if tx_type in self.__class__._tx_sticker_cache:
            return self.__class__._tx_sticker_cache[tx_type]
        
        return None


    def _determine_tx_type(self, tx_data: Dict[str, Any]) -> str:
        if tx_data.get('is_coinbase', False):
            return 'coinbase'
        
        outputs = tx_data.get('outputs', [])
        for output in outputs:
            event = output.get('event')
            if event == 'POST':
                return 'post'
            elif event == 'COMMENT':
                return 'comment'
            elif event == 'PAYOUT':
                return 'payout'

        return 'regular'


    def _qr_code(self, txid: str) -> Image.Image:
        qr_data = self.qr_prefix + txid
        qr_bytes = generated_receipt.generate_qr_code(qr_data)
        return Image.open(BytesIO(qr_bytes))


    def _format_tsar_amount(self, amount: Any) -> str:
        amount_str = str(amount)
        return generated_receipt.format_tsar_amount(amount_str, CFG.TSAR)


    def _draw_amount_with_style(
        self,
        draw: ImageDraw.ImageDraw,
        x: int, y: int,
        amount: Any,
        font: ImageFont.FreeTypeFont,
        normal_color: Tuple[int, int, int] = (3, 95, 166),
        decimal_color: Tuple[int, int, int] = (68, 134, 183),
        unit_color: Tuple[int, int, int] = (62, 62, 62)
        ) -> int:
        
        integer_part, decimal_part, unit = generated_receipt.split_amount_parts(str(amount), CFG.TSAR)
        
        # integer
        draw.text((x, y), integer_part, font=font, fill=normal_color)
        x += draw.textlength(integer_part, font=font)
        
        # Koma
        draw.text((x, y), ',', font=font, fill=normal_color)
        x += draw.textlength(',', font=font)
        
        # Decimal efect
        original_x = x
        offset = 1  # offset
        for i in range(3):
            offset_x = original_x + (i * offset / 3)
            color_shade = (
                min(255, decimal_color[0] + i * 20),
                min(255, decimal_color[1] + i * 20),
                min(255, decimal_color[2] + i * 20)
            )
            draw.text((offset_x, y), decimal_part, font=font, fill=color_shade)
        
        # Main
        draw.text((original_x + offset, y), decimal_part, font=font, fill=decimal_color)
        x = original_x + draw.textlength(decimal_part, font=font) + offset
    
        # Unit (TSAR)
        draw.text((x + 5, y), unit, font=font, fill=unit_color)
        total_text = f"{integer_part},{decimal_part}{unit}"
        return draw.textlength(total_text, font=font) + offset


    def _format_datetime(self, timestamp: int) -> str:
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime("%B %d, %Y - %H:%M:%S")


    def _truncate_text(self, text: Any, max_length: int = 64) -> str:
        text_str = str(text) if text else ""
        return generated_receipt.truncate_text(text_str, max_length)


    def _draw_txid_grid(self, draw, txid, x_start, y_start):
        grid_data = generated_receipt.draw_txid_grid_data(
            txid, x_start, y_start, 18, 25, 15
        )
        
        for char, x, y, color in grid_data.char_positions:
            draw.text((x, y), char, font=self.monospace_font, fill=color)
        return y_start + 4 * grid_data.line_height + 15


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

        row_data = generated_receipt.draw_table_row_data(
        y_position, label, value, is_amount,
        str(amount_value) if amount_value else None, page_width
        )
        
        # Draw label
        draw.text((50, row_data.y_position), row_data.label, 
                font=font_label, fill=row_data.label_color)
        
        # Draw value
        if is_amount and row_data.amount_value:
            value_width = draw.textlength(row_data.value, font=font_value)
            self._draw_amount_with_style(draw,page_width - 50 - value_width, row_data.y_position, 
                                        row_data.amount_value, font_value)
        else:
            value_width = draw.textlength(row_data.value, font=font_value)
            draw.text((page_width - 50 - value_width, row_data.y_position), 
                    row_data.value, font=font_value, fill=row_data.value_color)
        
        # Draw divider
        y_position = row_data.y_position + 20
        draw.line([(50, y_position), (page_width - 50, y_position)], 
                fill=row_data.line_color, width=1)
        
        return y_position + 10


    def _add_status_stamp(self, img: Image.Image, status: str) -> Image.Image:
        rotated_stamp = self.__class__._get_rotated_stamp(status)
        if not rotated_stamp:
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
            
        # Position
        base_x = 530
        base_y = 100
        
        offset_x = getattr(rotated_stamp, 'offset_x', 0)
        offset_y = getattr(rotated_stamp, 'offset_y', 0)
        
        pos_x = base_x + offset_x
        pos_y = base_y + offset_y
        
        original_size = 180
        width_diff = rotated_stamp.width - original_size
        height_diff = rotated_stamp.height - original_size
        
        pos_x -= width_diff // 2
        pos_y -= height_diff // 2
        
        img_width, img_height = img.size
        stamp_width, stamp_height = rotated_stamp.size
        
        pos_x = max(0, min(pos_x, img_width - stamp_width))
        pos_y = max(0, min(pos_y, img_height - stamp_height))
        
        if rotated_stamp.mode == 'RGBA':
            img.paste(rotated_stamp, (pos_x, pos_y), rotated_stamp)
        else:
            img.paste(rotated_stamp, (pos_x, pos_y))
        
        return img


    def _draw_pool_label(
        self, draw, y_position, address, formatted_address, 
        right_text, font_left, font_right, page_width, 
        is_amount=False, amount_value=None
        ):
        
        is_pool_address = len(address) == 64 if address else False
        
        if is_amount and amount_value is not None:
            amount_str = self._format_tsar_amount(amount_value)
            right_text_width = draw.textlength(amount_str, font_right)
        else:
            right_text_width = draw.textlength(right_text, font_right)
        
        address_text_width = draw.textlength(formatted_address, font_left)
        draw.text((50, y_position), formatted_address, font=font_left, fill=(62, 62, 62))
        
        if is_pool_address:
            pool_text = "-> Pool Address"
            pool_text_width = draw.textlength(pool_text, font_left)
            pool_x = 50 + address_text_width + 5
            if pool_x + pool_text_width < page_width - 50 - right_text_width - 10:
                draw.text((pool_x, y_position), pool_text, 
                        font=font_left, fill=(173, 47, 198))  # Highlight
        
        if is_amount and amount_value is not None:
            amount_x = page_width - 50 - right_text_width
            self._draw_amount_with_style(draw, amount_x, y_position, 
                                        amount_value, font_right)
        else:
            text_x = page_width - 50 - right_text_width
            draw.text((text_x, y_position), right_text, font=font_right, fill=(62, 62, 62))
        
        y_position += 20
        draw.line([(50, y_position), (page_width - 50, y_position)], fill=(195, 195, 195), width=1)
        return y_position + 10


    def _draw_header_and_txid_grid(self, draw, tx_data, width, txid, status) -> int:
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
        
        y_position = self._draw_txid_grid(draw, txid, 205, 118)
        
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
        return y_position + 20


    def _draw_inputs_section(self, draw, tx_data, y_position, width) -> int:
        draw.text((50, y_position), "Sender", font=self.normal_font, fill=(232, 114, 35))
        y_position += 40

        inputs = tx_data.get('inputs', [])
        if inputs:
            input_groups = {}
            for inp in inputs:
                addr = inp.get('address')
                if addr not in input_groups:
                    input_groups[addr] = []
                input_groups[addr].append(inp)
            
            for addr, utxos in list(input_groups.items())[:3]:  # Max 3 address
                formatted_addr = generated_receipt.pool_address(addr)
                utxo_count = len(utxos)
                utxo_text = f"Used {utxo_count} UTXO{'s' if utxo_count != 1 else ''}"
                y_position = self._draw_pool_label(
                    draw, y_position, 
                    addr, f"- {formatted_addr}", 
                    utxo_text, 
                    self.small_font, self.small_font, width
                )
            
            total_input = sum(inp.get('amount', 0) for inp in inputs)
            y_position = self._draw_table_row(draw, y_position, "Total Input :", 
                                            self._format_tsar_amount(total_input), 
                                            self.small_font, self.small_font, width, 
                                            is_amount=True, amount_value=total_input)
            
        else:
            y_position = self._draw_table_row(draw, y_position, "Inputs :", 
                                            "Coinbase Transaction (No Inputs)", 
                                            self.small_font, self.small_font, width)
        return y_position + 20


    def _draw_outputs_section(self, draw, tx_data, y_position, width, input_addresses) -> int:
        draw.text((50, y_position), "Recipient", font=self.normal_font, fill=(232, 114, 35))
        y_position += 40
        
        outputs = tx_data.get('outputs', [])
        inputs = tx_data.get('inputs', [])
        if outputs:
            recipient_outputs = []
            change_outputs = []
            event_outputs = []
            
            for out in outputs:
                addr = out.get('address')
                if addr is None:
                    event_outputs.append(out)
                elif addr in input_addresses:
                    change_outputs.append(out)
                else:
                    recipient_outputs.append(out)
            
            if not inputs:  # Coinbase
                bonus = tx_data.get('bonus') or 0
                reward = sum(out.get('amount', 0) for out in outputs) - bonus
                recipient_groups = {}
                for out in outputs:
                    if out.get('address'):
                        addr = out.get('address')
                        if addr not in recipient_groups:
                            recipient_groups[addr] = []
                        recipient_groups[addr].append(out)
                
                for addr, outs in recipient_groups.items():
                    y_position = self._draw_table_row(draw, y_position, 
                                                    f"- {self._truncate_text(addr, 64)}", 
                                                    self._format_tsar_amount(reward), 
                                                    self.small_font, self.small_font, width,
                                                    is_amount=True, amount_value=reward)
                    
                if bonus > 0:
                    y_position = self._draw_table_row(draw, y_position, "Bonus :", 
                                                    self._format_tsar_amount(bonus), 
                                                    self.small_font, self.small_font, width,
                                                    is_amount=True, amount_value=bonus)
                y_position += 30

            else:
                if recipient_outputs:
                    recipient_groups = {}
                    for out in recipient_outputs:
                        addr = out.get('address', 'Unknown')
                        if addr not in recipient_groups:
                            recipient_groups[addr] = []
                        recipient_groups[addr].append(out)
                    
                    for addr, outs in recipient_groups.items():
                        total_addr = sum(o.get('amount', 0) for o in outs)
                        formatted_addr = generated_receipt.pool_address(addr)
                        y_position = self._draw_pool_label(
                            draw, y_position,
                            addr, f"- {formatted_addr}",
                            self._format_tsar_amount(total_addr),
                            self.small_font, self.small_font, width,
                            is_amount=True, amount_value=total_addr
                        )
                else:
                    y_position = self._draw_table_row(draw, y_position, "Recipient :", 
                                                    "No external recipients", 
                                                    self.small_font, self.small_font, width)
                
                fee = tx_data.get('fee') or 0
                y_position = self._draw_table_row(draw, y_position, "Fee ( Miner ) :", 
                                                self._format_tsar_amount(fee), 
                                                self.small_font, self.small_font, width,
                                                is_amount=True, amount_value=fee)
                y_position += 10
                end_x = width - 55
                line_length = 10

                draw.line([(end_x - line_length//2, y_position), 
                        (end_x + line_length//2, y_position)], 
                        fill=(62, 62, 62), width=2)

                draw.line([(end_x, y_position - line_length//2), 
                        (end_x, y_position + line_length//2)], 
                        fill=(62, 62, 62), width=2)
                
                y_position += 10
                    
                total_outputs = sum(out.get('amount', 0) for out in recipient_outputs)
                total_spend = total_outputs + fee
                y_position = self._draw_table_row(draw, y_position, "Total Spend :", 
                                                self._format_tsar_amount(total_spend), 
                                                self.small_font, self.small_font, width,
                                                is_amount=True, amount_value=total_spend)
        
        return y_position + 30


    def _draw_summary_section(self, draw, tx_data, y_position, inputs, outputs, input_addresses) -> Tuple[int, int]:
        summary_y_start = int(y_position)
        draw.text((50, summary_y_start), "Summary", font=self.normal_font, fill=(232, 114, 35))
        y_position = summary_y_start + 40
        summary_left_x = 50
        summary_width = 410

        total_input_val = sum(inp.get('amount', 0) for inp in inputs)

        if not inputs:  # coinbase
            bonus = tx_data.get('bonus') or 0
            reward = sum(out.get('amount', 0) for out in outputs) - bonus
            total_recipient_val = bonus + reward
            summary_lines = [("Mining Reward :", reward, False)]
            
            if bonus > 0:
                summary_lines.append(("Bonus :", bonus, "plus"))
                summary_lines.append(("", 0, "separator"))
                summary_lines.append(("Total Reward :", total_recipient_val, False))
                
        else:
            fee = tx_data.get('fee') or 0
            total_recipient_val = sum(out.get('amount', 0) for out in outputs 
                                    if out.get('address') and 
                                    out.get('address') not in input_addresses)
            change_amount = total_input_val - total_recipient_val - fee
            total_spend = total_recipient_val + fee
            summary_lines = [
                ("Total Input :", total_input_val, False),
                ("Total Spend :", total_spend, "minus"),
                ("", 0, "separator"),
                ("Change :", change_amount, False)
            ]

        current_y = int(y_position)
        for label, amount, sign_type in summary_lines:
            if sign_type == "separator":
                line_y = current_y + 5
                draw.line([(summary_left_x, line_y), (summary_left_x + summary_width, line_y)], 
                        fill=(195, 195, 195), width=1)
                current_y += 10
                continue
            
            draw.text((summary_left_x, current_y), label, 
                    font=self.small_font, fill=(62, 62, 62))
            
            amount_text = self._format_tsar_amount(amount)
            amount_width = draw.textlength(amount_text, font=self.small_font)
            
            if sign_type == "minus":
                sign = "-"
                sign_width = draw.textlength(sign, font=self.small_font)
                sign_x = summary_left_x + summary_width - amount_width - sign_width - 3
                draw.text((sign_x, current_y), sign, 
                        font=self.small_font, fill=(62, 62, 62))
            elif sign_type == "plus":
                sign = "+"
                sign_width = draw.textlength(sign, font=self.small_font)
                sign_x = summary_left_x + summary_width - amount_width - sign_width - 3
                draw.text((sign_x, current_y), sign, 
                        font=self.small_font, fill=(62, 62, 62))

            amount_x = summary_left_x + summary_width - amount_width
            self._draw_amount_with_style(draw, amount_x, current_y, 
                                        amount, self.small_font)
            current_y += 30

        return summary_y_start, current_y


    def _draw_stickers_qr_footer(self, img, draw, tx_data, txid, status, summary_y_start, current_y, width) -> Tuple[str, bytes]:
        # ============= TX TYPE STICKER =============
        if status == 'confirmed':
            sticker = self._get_tx_type_sticker(tx_data)
            if sticker:
                sticker_size = 185
                summary_height = current_y - summary_y_start
                sticker_y = summary_y_start + (summary_height - sticker_size) // 2
                sticker_x = 50 + 410 + 100
                if sticker.mode == 'RGBA':
                    img.paste(sticker, (sticker_x, sticker_y), sticker)
                else:
                    img.paste(sticker, (sticker_x, sticker_y))
                    
        current_y += 30
        
        # QR code
        qr_img = self._qr_code(txid)
        qr_size = 180
        qr_img = qr_img.resize((qr_size, qr_size), Image.Resampling.NEAREST)
        qr_x = width - 60 - qr_size
        summary_height = current_y - summary_y_start
        min_summary_height = qr_size

        if summary_height < min_summary_height:
            qr_y = summary_y_start + summary_height + 25
        else:
            qr_y = summary_y_start + (summary_height - qr_size) // 2

        min_qr_y = summary_y_start + 40
        qr_y = max(min_qr_y, int(qr_y))
        qr_x = int(qr_x)
        
        if qr_img.mode == 'RGBA':
            img.paste(qr_img, (qr_x, qr_y), qr_img)
        else:
            img.paste(qr_img, (qr_x, qr_y))

        # footer
        y_position = max(current_y, qr_y + qr_size) + 20

        scan_text = "Scan for details"
        scan_text_width = draw.textlength(scan_text, font=self.small_font)
        draw.text((qr_x + (qr_size - scan_text_width) // 2, qr_y + qr_size + 10),
                   scan_text, font=self.small_font, fill=(100, 100, 100))
        
        # ============= FOOTER =============
        footer_y = int(y_position + 20)

        # closing
        footer_text = "Generated by TsarChain Explorer"
        footer_width = draw.textlength(footer_text, font=self.small_font)
        draw.text(((width - footer_width) // 2, footer_y + 40), footer_text,
                 font=self.small_font, fill=(100, 100, 100))
        
        # ============= STATUS STAMP =============
        img = self._add_status_stamp(img, status)
        
        # ============= SAVE IMAGE =============
        output_filename = f"{txid[:64]}.jpg"
        output_path = os.path.join(self.path, output_filename)
        
        buffer = BytesIO()
        img.save(
            buffer, 
            format='JPEG',
            quality=85,
            optimize=True,
            progressive=True,
            subsampling=0
        )
        image_bytes = buffer.getvalue()
        
        with open(output_path, 'wb') as f:
            f.write(image_bytes)
            
        return output_path, image_bytes
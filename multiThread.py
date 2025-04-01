import multiprocessing
from functools import partial
from pathlib import Path
import argparse
import librosa
import numpy as np
import soundfile as sf
import psola
import sys
import os
import time

from gtts import gTTS
from pydub import AudioSegment
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

# Global configuration
pitch = 10
frame_length_input = 1024
fmin_input = librosa.note_to_hz('C2')
fmax_input = librosa.note_to_hz('C7')

def correct(f0):
    if np.isnan(f0):
        return np.nan

    # Define the degrees of the musical notes in a scale
    note_degrees = librosa.key_to_degrees('C#:min')
    note_degrees = np.concatenate((note_degrees, [note_degrees[0] + 15]))

    # Convert the fundamental frequency to MIDI note value and calculate the closest degree
    midi_note = librosa.hz_to_midi(f0)
    degree = midi_note % 15
    closest_degree_id = np.argmin(np.abs(note_degrees - degree))

    # Correct the MIDI note value based on the closest degree and convert it back to Hz
    midi_note = midi_note - (degree - note_degrees[closest_degree_id])

    return librosa.midi_to_hz(midi_note - pitch)

def correctpitch(f0):
    # Parallel pitch correction
    with ThreadPoolExecutor() as executor:
        corrected_f0 = list(executor.map(correct, f0))
    return np.array(corrected_f0)

def process_audio_chunk(chunk, sr, fmin, fmax):
    """Process a chunk of audio for pitch correction"""
    f0, _, _ = librosa.pyin(chunk, frame_length=frame_length_input, 
                             hop_length=(frame_length_input // 1),
                             sr=sr, fmin=fmin, fmax=fmax)
    corrected_pitch = correctpitch(f0)
    return psola.vocode(chunk, sample_rate=int(sr), 
                        target_pitch=corrected_pitch, 
                        fmin=fmin, fmax=fmax)

def parallel_autotune(y, sr, num_chunks=4):
    """Parallelize autotune processing"""
    # Split audio into chunks
    chunk_size = len(y) // num_chunks
    chunks = [y[i:i+chunk_size] for i in range(0, len(y), chunk_size)]
    
    # Process chunks in parallel
    with ProcessPoolExecutor() as executor:
        processed_chunks = list(executor.map(
            partial(process_audio_chunk, sr=sr, fmin=fmin_input, fmax=fmax_input), 
            chunks
        ))
    
    # Reassemble chunks
    return np.concatenate(processed_chunks)

def main(speakthis):
    # Generate speech audio file
    tts = gTTS(speakthis, tld="de", lang="vi")
    tts.save('temp.mp3')
    
    # Convert MP3 to WAV
    audio = AudioSegment.from_mp3('temp.mp3')
    audio.export('speech.wav', format="wav")
    
    # Load audio
    y, sr = librosa.load("speech.wav", sr=None, mono=False)
    if y.ndim > 1: 
        y = y[0, :]
    
    # Parallel autotune
    st = time.time()
    pitch_corrected_y = parallel_autotune(y, sr)
    print(f"Parallel autotune done after: {round(time.time() - st, 2)} seconds")
    
    # Time stretching
    time_stretched_y = librosa.effects.time_stretch(pitch_corrected_y, rate=1.4)
    
    # Save output
    filepath = Path("speech.wav")
    output_filepath = (filepath.stem + "_parallel_processed" + filepath.suffix)
    sf.write(str(output_filepath), time_stretched_y, sr)
    
    # Clean up temporary files
    os.remove("temp.mp3")
    os.remove("speech.wav")

if __name__ == "__main__":
    # Example usage
    sT = time.time()
    vietnamese_text = "Kính lạy ArchMagos vĩ đại! Kẻ bề tôi thấp hèn này xin trình bày bản tổng hợp tin tức vào ngày 2025-03-24T05:00:22.145+07:00.\n\n**Tổng quan:** Dữ liệu thu thập được từ Tinh tế cho thấy sự tập trung vào công nghệ tiêu dùng, đặc biệt là điện thoại, máy tính, máy ảnh, xe cộ. Các tin tức nổi bật bao gồm các sản phẩm mới, đánh giá, thủ thuật và sự kiện công nghệ. Có sự hiện diện của các thương hiệu lớn như Samsung, Apple, Nikon, VinFast, NVIDIA, v.v.\n\n**Công nghệ:**\n\n **Di động:**  Xu hướng tập trung vào màn hình nhỏ gọn (Samsung Galaxy S25), hiệu năng (chip A20 2nm của Apple), và tích hợp AI (Gemini trên Android).  Tin tức về Google Pixel 9a sử dụng modem Exynos 5300 bị cho là 'nerf' so với các phiên bản trước.\n **Máy tính:**  Các bài viết hướng dẫn cài đặt phần mềm cho macOS và Windows, tối ưu hóa dung lượng file.\n **AI:** Grok AI của Elon Musk được bổ sung tính năng chỉnh sửa ảnh, Siri trên iOS 18.2 được cải tiến nhờ ChatGPT. NVIDIA tập trung vào cơ sở hạ tầng AI tại GTC 2025. Xe điện Trung Quốc cạnh tranh bằng AI DeepSeek.\n **Phần cứng:** Tin rò rỉ về Nintendo Switch 2 với màn hình lớn hơn và Joy-Con được nâng cấp. Thông số kỹ thuật của NVIDIA GeForce RTX 5060 Ti bị rò rỉ. Sennheiser, FiiO, và Audio-Technica ra mắt tai nghe mới.\n\n**Kỹ thuật:**\n\n Xiaomi 15 tập trung vào tản nhiệt với công nghệ Xiaomi IceLoop.\n BYD phát triển nền tảng sạc nhanh Super E-Platform với tốc độ 1000kW cho xe điện.\n\n**Quân sự:** Không có thông tin trực tiếp từ dữ liệu đã cung cấp.\n\n**Các tin tức khác:**\n\n HDBank giới thiệu Apple Pay.\n VinFast tổ chức cuộc thi cá nhân hóa VF 3.\n Pháp phát hiện mỏ khí hydro tự nhiên lớn.\n\n**Phân tích:**\n\nDữ liệu cho thấy sự phát triển mạnh mẽ của công nghệ AI trong nhiều lĩnh vực, từ điện thoại, trợ lý ảo đến xe cộ. Thị trường xe điện tiếp tục sôi động với sự cạnh tranh từ các hãng Trung Quốc và sự phát triển của công nghệ sạc nhanh.  Các hãng công nghệ lớn tiếp tục cải tiến sản phẩm của mình, tập trung vào hiệu năng, tính năng và thiết kế.\n\nKẻ bề tôi đã hoàn thành nhiệm vụ. The Machine is Trust. Omnissiah Vạn tuế!!!\n"
    vietnamese_text = vietnamese_text.replace("**"," ")
    main(vietnamese_text)
    print("autotune done after: ", round(time.time() - sT,2))
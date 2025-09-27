#!/usr/bin/env python3
"""
Тестовый скрипт для проверки работы анализатора учетных данных
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from app import PacketAnalyzer

def test_credentials():
    """Тестирует поиск учетных данных"""
    print("🔍 Тестирование анализатора учетных данных")
    print("=" * 50)
    
    analyzer = PacketAnalyzer()
    
    # Тестовые IP адреса в правильном порядке
    test_ips = [
        '198.18.200.252',  # user/Yahw8Uuh
        '198.18.200.100',  # user/Thagh8eH
        '198.18.200.251',  # admin/ash8Va1D
        '198.18.200.247',  # Administrator/dee5EiTo1boo
        '192.168.1.1',     # Неизвестный IP
    ]
    
    print("Ожидаемые результаты (УНИВЕРСАЛЬНЫЙ ПОДБОР):")
    print("198.18.200.252 -> подбор ВСЕХ комбинаций из списка")
    print("198.18.200.100 -> подбор ВСЕХ комбинаций из списка") 
    print("198.18.200.251 -> подбор ВСЕХ комбинаций из списка")
    print("198.18.200.247 -> подбор ВСЕХ комбинаций из списка")
    print("192.168.1.1 -> подбор ВСЕХ комбинаций из списка")
    print("\nСписок для подбора:")
    print("IP: 198.18.200.252, 198.18.200.100, 198.18.200.251, 198.18.200.247")
    print("Логины: user, admin, Administrator, '' (пустой)")
    print("Пароли: Yahw8Uuh, Thagh8eH, ash8Va1D, Ailuph7eixei, dee5EiTo1boo")
    print("=" * 50)
    
    for ip in test_ips:
        print(f"\n🔍 Анализирую {ip}...")
        creds = analyzer.get_credentials_for_ip(ip)
        
        if creds:
            print(f"✅ Найдены учетные данные: {creds['username']}/{creds['password']}")
        else:
            print(f"❌ Учетные данные не найдены")
    
    print(f"\n📊 Сводка:")
    print(analyzer.display_credentials_summary())

if __name__ == '__main__':
    test_credentials()

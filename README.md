# Gandon-PRO

Нативный (C++20) дизассемблер / декомпилятор для Windows с видом и
поведением в стиле IDA Pro 9.

![platform](https://img.shields.io/badge/platform-Windows%20x64-blue)
![language](https://img.shields.io/badge/language-C%2B%2B20-blue)

## Возможности

- **Дизассемблер**: PE и ELF, x86, x86-64, ARM64 (через Capstone).
- **Декомпилятор**: x86-64 и ARM64, `switch` по таблицам переходов,
  SSE/AVX и x87 (float/double/long double), восстановление структур,
  enum и прототипов функций.
- **Вид в стиле IDA**: Gandon View-A (граф), Text Listing, Pseudocode-A,
  XREFs, Hex View-1, Imports/Exports/Strings/Resources, Local Types,
  миникарта графа, навигационная полоса.
- **Докинг-панели**: перетаскивание мышью, подсветка зоны стыковки,
  плавающие окна, сохранение раскладки.
- **Авто-анализ**: рекурсивный обход, именование thunk-ов, FLIRT-сигнатуры
  (`.pat`), распространение noreturn.
- **Отладчик**: Win32-отладчик с точками останова, чтением регистров и
  памяти живого процесса.
- **Сравнение бинарников** по функциям (name / hash / call-graph /
  similarity), отдельная панель и CLI `gandon_diff`.
- **Python-консоль**, управляющая всей программой (навигация, правки,
  отладчик, типы, диф) — двусторонняя связь с GUI.
- Патч байтов, Undo/Redo на всё (патчи + переименования + комментарии),
  сохранение базы анализа `.gnd`.

Полный список изменений — в [`CHANGELOG.md`](CHANGELOG.md).

## Сборка (Windows, MSVC / Visual Studio 2022)

```powershell
cmake -S cpp -B cpp\build -G "Visual Studio 17 2022" -A x64
cmake --build cpp\build --config Release --target gandon_gui
```

Нужен [Capstone](https://github.com/capstone-engine/capstone) (заголовки +
`capstone.dll`/`capstone.lib`). Варианты:

- положить в `cpp\third_party\capstone\{include,lib}` — CMake подхватит
  сам через `GANDON_CAPSTONE_ROOT`;
- либо поставить через vcpkg (`vcpkg install capstone:x64-windows`) и
  передать `-DCMAKE_TOOLCHAIN_FILE=.../vcpkg.cmake`.

Без Capstone проект всё равно соберётся (встроенный урезанный декодер
x86), но ARM64 и точность x86 будут хуже.

Готовый `capstone.dll` нужно положить рядом с собранным `gandon_gui.exe`
(либо CMake скопирует его сам post-build, если библиотека была найдена
при конфигурации).

### Цели сборки

| Цель | Что это |
|---|---|
| `gandon_gui` | GUI |
| `gandon_cli` | загрузка и краткий обзор бинарника |
| `gandon_decompile` | декомпиляция из командной строки |
| `gandon_auto` | авто-анализ, FLIRT-сигнатуры (`--make-pat`/`--verify-pat`) |
| `gandon_diff` | сравнение двух бинарников по функциям |
| `gandon_ida_views` | IDA-подобные текстовые представления |
| `gandon_mcp_backend` | MCP-сервер для управления программой снаружи |
| `gandon_core_tests`, `gandon_decompiler_tests`, `gandon_types_tests` | тесты (`ctest` после сборки) |

## Структура репозитория

```
cpp/src/          исходники (.cpp)
cpp/include/gandon/   заголовки (.hpp/.h)
cpp/tests/         тесты
cpp/plugins/       нативный пример-плагин, MCP-плагин, Python-плагины для GUI
cpp/mcp/           отдельный MCP-сервер (Python)
cpp/assets/        иконка
cpp/CMakeLists.txt
```

## Запуск готовой сборки

Нужны: `gandon_gui.exe`, `capstone.dll` рядом с ним, папка
`plugins\python` (встроенная Python-консоль), и опционально Python в
PATH. Папка `signatures\*.pat` рядом с exe — для FLIRT-сигнатур.

## Лицензия

Добавьте файл `LICENSE` с условиями, на которых распространяете проект.

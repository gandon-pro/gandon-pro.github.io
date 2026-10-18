# Тестовая подпись GandonMemory

Подписанный файл: `out\GandonMemory.sys`.
Публичный сертификат: `out\GandonMemory-Test.cer`.
Отпечаток сертификата: `8E1169F142C0B81205EB7A365D7563FF4A796696`.
Сертификат действует до 18 октября 2027 года. Закрытый ключ остался в хранилище текущего пользователя и не экспортировался.

Драйвер подписан, но пока не загружен. Сертификат пока не установлен в доверенные хранилища компьютера. Тестовый режим Windows не включался.

## Что сделать

1. Если включён BitLocker/шифрование устройства, заранее убедись, что у тебя сохранён ключ восстановления: изменение Secure Boot может вызвать его запрос.
2. В настройках UEFI/BIOS отключи Secure Boot для тестового режима. Остальные настройки защиты менять не нужно.
3. Вернись в Windows и открой PowerShell **от имени администратора**. Выполни:

```powershell
Set-Location -LiteralPath 'C:\path\to\Gandon-PRO\kernel'
certutil.exe -addstore -f Root '.\out\GandonMemory-Test.cer'
certutil.exe -addstore -f TrustedPublisher '.\out\GandonMemory-Test.cer'
bcdedit.exe /set testsigning on
```

Каждая команда должна завершиться успешно. Если BCDEdit пишет, что значение защищено политикой Secure Boot, настройка Secure Boot ещё включена. Пока команда не прошла, к загрузке драйвера не переходи.

4. Перезагрузи компьютер: TESTSIGNING действует только после перезагрузки. На рабочем столе может появиться надпись «Тестовый режим».
5. Снова открой PowerShell от имени администратора, перейди в ту же папку `kernel` и выполни:

```powershell
.\load-driver.ps1
```

Если PowerShell запрещает выполнение скрипта, вместо него выполни эти команды непосредственно в той же административной сессии:

```powershell
$driverImage = (Resolve-Path -LiteralPath '.\out\GandonMemory.sys').Path
sc.exe create GandonMemory type= kernel start= demand binPath= $driverImage
sc.exe start GandonMemory
sc.exe query GandonMemory
```

Если служба уже существует, повторять `create` не нужно. Не заменяй существующую службу с другим путём. В выводе `query` ожидается `RUNNING`. При любой ошибке сохрани её номер и текст — загрузка ещё не подтверждена.

Служба имеет ручной запуск. В версии 3.2 диалог установки и kernel-канал входят в GUI. Драйвер необязателен; без него используется ReadProcessMemory.

## Как отменить

В административном PowerShell:

```powershell
sc.exe stop GandonMemory
sc.exe delete GandonMemory
bcdedit.exe /set testsigning off
certutil.exe -delstore Root 8E1169F142C0B81205EB7A365D7563FF4A796696
certutil.exe -delstore TrustedPublisher 8E1169F142C0B81205EB7A365D7563FF4A796696
```

После успешного отключения тестового режима перезагрузи Windows, затем верни Secure Boot в исходное включённое состояние. Если остановка службы не удалась, не удаляй загруженный `.sys`: сначала перезагрузи компьютер.

Официальная документация Microsoft:
- https://learn.microsoft.com/windows-hardware/drivers/install/the-testsigning-boot-configuration-option
- https://learn.microsoft.com/windows-hardware/drivers/install/installing-a-test-certificate-on-a-test-computer

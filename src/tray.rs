use crate::proxy::AppState;
use crate::queue::QueueItemStatus;
use std::sync::Arc;

const TRAY_ICON_RGBA: &[u8] = include_bytes!("../static/tray-32.rgba");

/// Returns the 32x32 RGBA icon of Olórin the Grey with his raised glowing staff.
/// When `has_pending` is true, overlays a bright amber notification dot in the top-left corner.
fn render_icon_rgba(has_pending: bool) -> Vec<u8> {
    let size = 32usize;
    let mut rgba = TRAY_ICON_RGBA.to_vec();

    let set_px = |buf: &mut [u8], x: usize, y: usize, r: u8, g: u8, b: u8, a: u8| {
        if x < size && y < size {
            let idx = (y * size + x) * 4;
            buf[idx] = r;
            buf[idx + 1] = g;
            buf[idx + 2] = b;
            buf[idx + 3] = a;
        }
    };

    // Notification badge dot in top-left corner if pending items exist
    if has_pending {
        let cx = 7i32;
        let cy = 7i32;
        for y in 1..14 {
            for x in 1..14 {
                let d2 = (x as i32 - cx).pow(2) + (y as i32 - cy).pow(2);
                if d2 <= 25 && d2 > 16 {
                    set_px(&mut rgba, x, y, 15, 23, 42, 255);
                } else if d2 <= 16 {
                    set_px(&mut rgba, x, y, 245, 158, 11, 255);
                }
            }
        }
    }

    rgba
}

fn count_pending(state: &AppState) -> usize {
    state
        .store
        .snapshot()
        .queue
        .iter()
        .filter(|q| {
            matches!(
                q.status,
                QueueItemStatus::Pending | QueueItemStatus::ApprovedForBatch
            )
        })
        .count()
}

#[cfg(target_os = "linux")]
pub fn spawn_tray(
    state: Arc<AppState>,
    port: u16,
    on_open: Arc<dyn Fn() + Send + Sync>,
) {
    use ksni::blocking::TrayMethods;

    struct OlorinTray {
        port: u16,
        pending_count: usize,
        on_open: Arc<dyn Fn() + Send + Sync>,
    }

    impl ksni::Tray for OlorinTray {
        fn id(&self) -> String {
            "gitolorin".into()
        }

        fn title(&self) -> String {
            if self.pending_count > 0 {
                format!("gitOlorin (:{}) — {} pendiente(s)", self.port, self.pending_count)
            } else {
                format!("gitOlorin (:{}) — Proxy activo", self.port)
            }
        }

        fn icon_pixmap(&self) -> Vec<ksni::Icon> {
            let rgba = render_icon_rgba(self.pending_count > 0);
            let mut argb = Vec::with_capacity(rgba.len());
            for chunk in rgba.chunks_exact(4) {
                argb.push(chunk[3]); // A
                argb.push(chunk[0]); // R
                argb.push(chunk[1]); // G
                argb.push(chunk[2]); // B
            }
            vec![ksni::Icon {
                width: 32,
                height: 32,
                data: argb,
            }]
        }

        fn activate(&mut self, _x: i32, _y: i32) {
            (self.on_open)();
        }

        fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
            use ksni::menu::*;
            vec![
                StandardItem {
                    label: "🛡️ Abrir gitOlorin".into(),
                    activate: Box::new(|this: &mut Self| {
                        (this.on_open)();
                    }),
                    ..Default::default()
                }
                .into(),
                StandardItem {
                    label: format!("📋 Cola: {} pendiente(s)", self.pending_count),
                    activate: Box::new(|this: &mut Self| {
                        (this.on_open)();
                    }),
                    ..Default::default()
                }
                .into(),
                CheckmarkItem {
                    label: "⚡ Inicio automático".into(),
                    checked: crate::autostart::is_autostart_enabled(),
                    activate: Box::new(|_| {
                        let next = !crate::autostart::is_autostart_enabled();
                        let _ = crate::autostart::set_autostart(next);
                    }),
                    ..Default::default()
                }
                .into(),
                MenuItem::Separator,
                StandardItem {
                    label: "❌ Salir (detener proxy)".into(),
                    activate: Box::new(|_| {
                        println!("gitOlorin detenido desde el System Tray.");
                        std::process::exit(0);
                    }),
                    ..Default::default()
                }
                .into(),
            ]
        }
    }

    std::thread::spawn(move || {
        let initial_pending = count_pending(&state);
        let tray = OlorinTray {
            port,
            pending_count: initial_pending,
            on_open,
        };

        let handle = match tray.spawn() {
            Ok(h) => {
                println!("   └─ System Tray        : ✅ Activo (StatusNotifierItem / D-Bus)");
                h
            }
            Err(e) => {
                eprintln!("[!] System Tray no disponible en esta sesión: {}", e);
                return;
            }
        };

        let mut last_pending = initial_pending;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let cur_pending = count_pending(&state);
            if cur_pending != last_pending {
                last_pending = cur_pending;
                handle.update(|t| {
                    t.pending_count = cur_pending;
                });
            }
        }
    });
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_tray(
    state: Arc<AppState>,
    port: u16,
    on_open: Arc<dyn Fn() + Send + Sync>,
) {
    use tray_icon::{
        menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
        Icon, TrayIconBuilder, TrayIconEvent,
    };

    std::thread::spawn(move || {
        let menu = Menu::new();
        let open_item = MenuItem::new("🛡️ Abrir gitOlorin", true, None);
        let initial_pending = count_pending(&state);
        let status_item = MenuItem::new(
            format!("📋 Cola: {} pendiente(s)", initial_pending),
            true,
            None,
        );
        let sep = PredefinedMenuItem::separator();
        let quit_item = MenuItem::new("❌ Salir (detener proxy)", true, None);

        let _ = menu.append(&open_item);
        let _ = menu.append(&status_item);
        let _ = menu.append(&sep);
        let _ = menu.append(&quit_item);

        let tooltip = if initial_pending > 0 {
            format!(
                "gitOlorin (:{}) — {} pendiente(s) de aprobación",
                port, initial_pending
            )
        } else {
            format!("gitOlorin (:{}) — Proxy activo", port)
        };

        let icon = Icon::from_rgba(render_icon_rgba(initial_pending > 0), 32, 32)
            .expect("valid 32x32 RGBA tray icon");

        let tray = match TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip(tooltip)
            .with_icon(icon)
            .build()
        {
            Ok(t) => {
                println!("   └─ System Tray        : ✅ Activo");
                t
            }
            Err(e) => {
                eprintln!("[!] System Tray no disponible en esta sesión: {}", e);
                return;
            }
        };

        let menu_rx = MenuEvent::receiver();
        let tray_rx = TrayIconEvent::receiver();
        let mut last_pending = initial_pending;
        let mut ticks = 0u32;

        loop {
            while let Ok(ev) = menu_rx.try_recv() {
                if ev.id == open_item.id() || ev.id == status_item.id() {
                    on_open();
                } else if ev.id == quit_item.id() {
                    println!("🧙‍♂️ gitOlorin detenido desde el System Tray.");
                    std::process::exit(0);
                }
            }

            while let Ok(ev) = tray_rx.try_recv() {
                if matches!(ev, TrayIconEvent::Click { .. }) {
                    on_open();
                }
            }

            ticks += 1;
            if ticks >= 20 {
                ticks = 0;
                let cur_pending = count_pending(&state);
                if cur_pending != last_pending {
                    last_pending = cur_pending;
                    status_item.set_text(format!("📋 Cola: {} pendiente(s)", cur_pending));
                    let new_tip = if cur_pending > 0 {
                        format!(
                            "gitOlorin (:{}) — {} pendiente(s) de aprobación",
                            port, cur_pending
                        )
                    } else {
                        format!("gitOlorin (:{}) — Proxy activo", port)
                    };
                    let _ = tray.set_tooltip(Some(new_tip));
                    let new_icon = Icon::from_rgba(render_icon_rgba(cur_pending > 0), 32, 32)
                        .expect("valid 32x32 RGBA tray icon");
                    let _ = tray.set_icon(Some(new_icon));
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });
}

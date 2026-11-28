use std::collections::HashSet;
use std::time::Duration;

use gpui::{
    Bounds, Context, CursorStyle, DispatchPhase, IntoElement, MouseButton, MouseDownEvent,
    MouseExitEvent, MouseMoveEvent, MouseUpEvent, Pixels, Point, Window, canvas, div, point,
    prelude::*, px, rgb, size,
};
use nyaterm_ui::NyaButton;
use rust_i18n::t;

use super::RemoteDesktopFullscreenWindow;

pub(super) const INITIAL_DISPLAY: Duration = Duration::from_secs(3);
pub(super) const HIDE_DELAY: Duration = Duration::from_millis(800);
const TOOLBAR_WIDTH: f32 = 280.;
const TOOLBAR_HEIGHT: f32 = 64.;
const REVEAL_HEIGHT: f32 = 8.;
// The detached window captures this chord directly, independently of workspace bindings.
const EXIT_SHORTCUT: &str = "Ctrl+Shift+Alt+F11";

pub(super) struct FullscreenToolbarState {
    pub(super) visible: bool,
    pub(super) hovered: bool,
    generation: u64,
    local_buttons: HashSet<MouseButton>,
}

impl Default for FullscreenToolbarState {
    fn default() -> Self {
        Self {
            visible: true,
            hovered: false,
            generation: 0,
            local_buttons: HashSet::new(),
        }
    }
}

impl FullscreenToolbarState {
    /// Returns a hover transition. A drag must not reveal the hidden toolbar.
    pub(super) fn pointer(&mut self, inside: bool, dragging: bool) -> Option<bool> {
        let hovered = inside && (self.visible || !dragging);
        if self.hovered == hovered {
            return None;
        }
        self.hovered = hovered;
        self.generation += 1;
        if hovered {
            self.visible = true;
        }
        Some(hovered)
    }

    pub(super) fn hide_generation(&mut self) -> u64 {
        self.generation += 1;
        self.generation
    }

    pub(super) fn hide(&mut self, generation: u64) -> bool {
        if generation != self.generation || self.hovered || !self.local_buttons.is_empty() {
            return false;
        }
        std::mem::replace(&mut self.visible, false)
    }

    fn bounds(&self, viewport: Bounds<Pixels>) -> Bounds<Pixels> {
        let width = viewport.size.width.min(px(TOOLBAR_WIDTH));
        Bounds::new(
            point(
                viewport.origin.x + (viewport.size.width - width) / 2.,
                viewport.origin.y,
            ),
            size(
                width,
                px(if self.visible {
                    TOOLBAR_HEIGHT
                } else {
                    REVEAL_HEIGHT
                }),
            ),
        )
    }
}

impl RemoteDesktopFullscreenWindow {
    pub(super) fn fullscreen_toolbar_input_bounds(
        &self,
        window: &Window,
    ) -> Option<Bounds<Pixels>> {
        self.toolbar.visible.then(|| {
            self.toolbar
                .bounds(Bounds::new(Point::default(), window.viewport_size()))
        })
    }

    pub(super) fn initialize_toolbar(&mut self, window: &Window, cx: &mut Context<Self>) {
        let viewport = Bounds::new(Point::default(), window.viewport_size());
        if self
            .toolbar
            .bounds(viewport)
            .contains(&window.mouse_position())
        {
            self.toolbar.pointer(true, false);
        } else {
            self.schedule_toolbar_hide(INITIAL_DISPLAY, cx);
        }
    }

    pub(super) fn deactivate_toolbar(&mut self, cx: &mut Context<Self>) {
        self.toolbar.local_buttons.clear();
        self.toolbar.pointer(false, false);
        if self.toolbar.visible {
            self.schedule_toolbar_hide(HIDE_DELAY, cx);
        }
    }

    pub(super) fn schedule_toolbar_hide(&mut self, delay: Duration, cx: &mut Context<Self>) {
        let generation = self.toolbar.hide_generation();
        self.toolbar_hide_task = Some(cx.spawn(async move |this, cx| {
            cx.background_executor().timer(delay).await;
            let _ = this.update(cx, |this, cx| {
                if this.toolbar.hide(generation) {
                    cx.notify();
                }
            });
        }));
    }

    fn toolbar_pointer(&mut self, inside: bool, dragging: bool, cx: &mut Context<Self>) {
        match self.toolbar.pointer(inside, dragging) {
            Some(true) => {
                self.toolbar_hide_task = None;
                // Moving onto a local control must not strand a remotely held
                // button when its eventual mouse-up is consumed by this overlay.
                let _ = self.app.update(cx, |app, _| {
                    app.release_remote_keys(&self.session_id);
                });
                cx.notify();
            }
            Some(false) => self.schedule_toolbar_hide(HIDE_DELAY, cx),
            None => {}
        }
    }

    pub(super) fn fullscreen_toolbar_pointer_observer(
        &self,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        let view = cx.weak_entity();
        canvas(
            |_, _, _| (),
            move |bounds, _, window, _| {
                let move_view = view.clone();
                window.on_mouse_event(move |event: &MouseMoveEvent, phase, _, cx| {
                    if phase != DispatchPhase::Capture {
                        return;
                    }
                    let _ = move_view.update(cx, |this, cx| {
                        if event.pressed_button.is_none() && !this.toolbar.local_buttons.is_empty()
                        {
                            this.toolbar.local_buttons.clear();
                            // Recover a mouse-up lost while outside the native window.
                            if !this.toolbar.hovered {
                                this.schedule_toolbar_hide(HIDE_DELAY, cx);
                            }
                        }
                        let inside = this.toolbar.bounds(bounds).contains(&event.position);
                        let was_visible = this.toolbar.visible;
                        this.toolbar_pointer(inside, event.pressed_button.is_some(), cx);
                        if !this.toolbar.local_buttons.is_empty()
                            || (!was_visible && this.toolbar.visible)
                        {
                            cx.stop_propagation();
                        }
                    });
                });
                let down_view = view.clone();
                window.on_mouse_event(move |event: &MouseDownEvent, phase, _, cx| {
                    if phase == DispatchPhase::Capture {
                        let _ = down_view.update(cx, |this, cx| {
                            if this.toolbar.visible
                                && this.toolbar.bounds(bounds).contains(&event.position)
                            {
                                this.toolbar_pointer(true, false, cx);
                                this.toolbar.local_buttons.insert(event.button);
                            }
                        });
                    }
                });
                let up_view = view.clone();
                window.on_mouse_event(move |event: &MouseUpEvent, phase, _, cx| {
                    if phase == DispatchPhase::Capture {
                        let _ = up_view.update(cx, |this, cx| {
                            if this.toolbar.local_buttons.remove(&event.button)
                                && !this.toolbar.bounds(bounds).contains(&event.position)
                            {
                                // A press begun locally must not finish on the remote surface.
                                cx.stop_propagation();
                                this.schedule_toolbar_hide(HIDE_DELAY, cx);
                            }
                        });
                    }
                });
                let exit_view = view.clone();
                window.on_mouse_event(move |_: &MouseExitEvent, phase, _, cx| {
                    if phase == DispatchPhase::Capture {
                        let _ = exit_view.update(cx, |this, cx| {
                            this.deactivate_toolbar(cx);
                        });
                    }
                });
            },
        )
        .absolute()
        .inset_0()
    }

    pub(super) fn fullscreen_toolbar(
        &self,
        window: &Window,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        let palette = self
            .app
            .read_with(cx, |app, _| app.theme_palette())
            .unwrap();
        let bounds = self
            .toolbar
            .bounds(Bounds::new(Point::default(), window.viewport_size()));
        let shell = div()
            .absolute()
            .left(bounds.origin.x)
            .top_0()
            .w(bounds.size.width)
            .h(bounds.size.height)
            .overflow_hidden();
        if !self.toolbar.visible {
            // No occluding hitbox here: remote drags can cross the reveal area.
            return shell
                .flex()
                .justify_center()
                .child(
                    div()
                        .w(px(40.))
                        .h(px(3.))
                        .rounded_b_md()
                        .bg(rgb(palette.text_muted)),
                )
                .into_any_element();
        }
        let mut toolbar = shell
            .id("rdp-fullscreen-toolbar")
            .debug_selector(|| "rdp-fullscreen-toolbar".into())
            .occlude()
            .cursor(CursorStyle::Arrow)
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .gap_1()
            .px_2()
            .rounded_b_md()
            .bg(rgb(palette.surface))
            .border_1()
            .border_color(rgb(palette.border))
            .on_any_mouse_down(|_, _, cx| cx.stop_propagation())
            .on_mouse_move(|_, _, cx| cx.stop_propagation())
            .on_scroll(|_, _, cx| cx.stop_propagation())
            .child(
                NyaButton::new("rdp-fullscreen-exit", t!("remoteDesktop.exitFullscreen"))
                    .icon("icons/session/exit-fullscreen.svg")
                    .small()
                    .full_width()
                    .tooltip(format!(
                        "{} ({EXIT_SHORTCUT})",
                        t!("remoteDesktop.exitFullscreen")
                    ))
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.toolbar_hide_task = None;
                        let _ = this.app.update(cx, |app, cx| {
                            app.exit_remote_desktop_fullscreen_from_window(
                                &this.session_id,
                                window.window_handle(),
                                cx,
                            );
                        });
                        cx.stop_propagation();
                    })),
            )
            .child(
                div()
                    .text_size(px(11.))
                    .text_color(rgb(palette.text_muted))
                    .child(EXIT_SHORTCUT),
            );
        toolbar
            .interactivity()
            .on_any_mouse_up(|_, _, cx| cx.stop_propagation());
        toolbar.into_any_element()
    }
}

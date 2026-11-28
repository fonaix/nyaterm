use std::path::Path;

use gpui::{
    AppContext as _, Context, DevicePixels, Entity, IntoElement, Modifiers, MouseButton,
    MouseDownEvent, MouseMoveEvent, MouseUpEvent, PlatformInput, Render, ScrollDelta, ScrollEvent,
    TestAppContext, VisualTestContext, Window, div, point, px, size,
};
use nyaterm_core::test_support::TestTempDir;
use nyaterm_remote_desktop::{Framebuffer, RDP_FRAMEBUFFER_LIMITS, RemoteDesktopViewState};
use nyaterm_ui::NyaWindowHandle;

use super::RemoteDesktopFullscreenWindow;
use super::toolbar::{FullscreenToolbarState, HIDE_DELAY, INITIAL_DISPLAY};
use crate::features::NyaTermApp;
use crate::features::remote_desktop::state::frame_source::RemoteDesktopFrameSource;
use crate::features::test_support::app_with_visible_local_session;
use crate::test_support::TestAppCleanup;

#[test]
fn hover_invalidates_old_hide_deadlines_and_remote_drags_do_not_reveal() {
    let mut state = FullscreenToolbarState::default();
    let initial = state.hide_generation();
    assert!(state.visible);
    assert_eq!(state.pointer(true, false), Some(true));
    assert!(!state.hide(initial));
    assert_eq!(state.pointer(false, false), Some(false));
    let old_leave = state.hide_generation();
    assert_eq!(state.pointer(true, false), Some(true));
    assert_eq!(state.pointer(false, false), Some(false));
    let latest_leave = state.hide_generation();
    assert!(!state.hide(old_leave));
    assert!(state.hide(latest_leave));
    assert_eq!(state.pointer(true, true), None);
    assert!(!state.visible);
    assert_eq!(state.pointer(true, false), Some(true));
    assert!(state.visible);
}

struct EmptyView;

impl Render for EmptyView {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
    }
}

fn fixture(
    cx: &mut TestAppContext,
    path: &Path,
) -> (
    Entity<NyaTermApp>,
    Entity<RemoteDesktopFullscreenWindow>,
    NyaWindowHandle,
) {
    cx.update(nyaterm_ui::init_components);
    let app = app_with_visible_local_session(cx, path, "remote");
    let main = cx.add_window(|window, cx| {
        let view = cx.new(|_| EmptyView);
        nyaterm_ui::nya_root(view, window, cx)
    });
    app.update(cx, |app, _| {
        app.shell.remember_main_window(main);
        app.remote_desktop.insert_connecting("remote".into());
        app.remote_desktop.fullscreen_session = Some("remote".into());
    });
    let mut view = None;
    let host = cx.add_window(|window, cx| {
        let entity = cx.new(|cx| {
            RemoteDesktopFullscreenWindow::new(app.downgrade(), "remote".into(), window, cx)
        });
        view = Some(entity.clone());
        nyaterm_ui::nya_root(entity, window, cx)
    });
    app.update(cx, |app, _| {
        app.remote_desktop.fullscreen_window = Some(host)
    });
    cx.update_window(host.into(), |_, window, cx| {
        let _ = window.draw(cx);
    })
    .unwrap();
    cx.run_until_parked();
    (app, view.unwrap(), host)
}

fn connect_surface(app: &Entity<NyaTermApp>, host: NyaWindowHandle, cx: &mut TestAppContext) {
    cx.update_window(host.into(), |_, window, cx| {
        app.update(cx, |app, cx| {
            let framebuffer = Framebuffer::new(1, 8, 8, RDP_FRAMEBUFFER_LIMITS).unwrap();
            let texture = window
                .create_dynamic_texture(
                    size(DevicePixels(8), DevicePixels(8)),
                    framebuffer.pixels(),
                    32,
                )
                .unwrap();
            let session = app.remote_desktop.sessions.get_mut("remote").unwrap();
            session.state = RemoteDesktopViewState::Connected;
            session.framebuffer = Some(RemoteDesktopFrameSource::Rdp {
                width: 8,
                height: 8,
                id: nyaterm_remote_desktop::presentation::RemotePresentationId {
                    epoch: 1,
                    generation: 1,
                    sequence: 1,
                },
            });
            session.texture = Some(texture);
            cx.notify();
        });
        let focus = app.read(cx).remote_desktop.focus().clone();
        window.focus(&focus, cx);
        let _ = window.draw(cx);
    })
    .unwrap();
    cx.run_until_parked();
}

#[test]
fn toolbar_blocks_remote_mouse_input_without_resizing_or_stealing_hover_focus() {
    let root = TestTempDir::new("nyaterm-fullscreen-toolbar-input");
    let mut cx = TestAppContext::single();
    let _cleanup = TestAppCleanup::new(&cx);
    let (app, view, host) = fixture(&mut cx, root.path());
    connect_surface(&app, host, &mut cx);
    let viewport = app.read_with(&cx, |app, _| {
        app.remote_desktop.sessions["remote"].viewport.unwrap()
    });
    let mut visual = VisualTestContext::from_window(host.into(), &cx);
    visual.update(|window, cx| {
        let _ = window.draw(cx);
    });
    let toolbar_bounds = visual.debug_bounds("rdp-fullscreen-toolbar").unwrap();
    let over_toolbar = point(toolbar_bounds.center().x, toolbar_bounds.bottom() - px(6.));
    visual.simulate_mouse_move(over_toolbar, None, Modifiers::default());
    assert!(
        view.read_with(&cx, |view, _| view.toolbar.hovered),
        "toolbar bounds: {toolbar_bounds:?}, viewport: {viewport:?}"
    );
    app.read_with(&cx, |app, _| {
        assert!(
            app.remote_desktop.sessions["remote"].last_pointer.is_none(),
            "toolbar mouse move leaked"
        );
    });
    visual.simulate_mouse_down(over_toolbar, MouseButton::Right, Modifiers::default());
    app.read_with(&cx, |app, _| {
        assert!(
            app.remote_desktop.sessions["remote"].last_pointer.is_none(),
            "toolbar mouse down leaked"
        );
    });
    visual.simulate_mouse_up(over_toolbar, MouseButton::Right, Modifiers::default());
    app.read_with(&cx, |app, _| {
        assert!(
            app.remote_desktop.sessions["remote"].last_pointer.is_none(),
            "toolbar mouse up leaked"
        );
    });
    visual.simulate_event(ScrollEvent {
        position: over_toolbar,
        delta: ScrollDelta::Lines(point(0.25, 0.25)),
        ..Default::default()
    });
    visual.update(|window, cx| {
        let session = &app.read(cx).remote_desktop.sessions["remote"];
        assert!(
            session.last_pointer.is_none(),
            "toolbar pointer events reached the remote surface"
        );
        assert_eq!(session.wheel_remainder_x, 0.);
        assert_eq!(session.wheel_remainder_y, 0.);
        assert!(app.read(cx).remote_desktop.focus().is_focused(window));
    });
    let remote_point = point(viewport.size.width / 2., px(120.));
    visual.simulate_mouse_down(over_toolbar, MouseButton::Left, Modifiers::default());
    visual.simulate_mouse_move(remote_point, Some(MouseButton::Left), Modifiers::default());
    visual.simulate_mouse_up(remote_point, MouseButton::Left, Modifiers::default());
    app.read_with(&cx, |app, _| {
        assert!(
            app.remote_desktop.sessions["remote"].last_pointer.is_none(),
            "a local press must not finish on the remote surface"
        );
    });
    visual.simulate_mouse_move(remote_point, None, Modifiers::default());
    cx.executor().advance_clock(HIDE_DELAY);
    cx.run_until_parked();
    assert!(!view.read_with(&cx, |view, _| view.toolbar.visible));
    visual.update(|window, cx| {
        let _ = window.draw(cx);
    });
    visual.simulate_mouse_move(
        point(viewport.size.width / 2., px(2.)),
        Some(MouseButton::Left),
        Modifiers::default(),
    );
    assert!(
        !view.read_with(&cx, |view, _| view.toolbar.visible),
        "remote drag revealed toolbar"
    );
    app.read_with(&cx, |app, _| {
        let session = &app.remote_desktop.sessions["remote"];
        assert!(
            session.last_pointer.is_some(),
            "remote surface did not receive input outside toolbar"
        );
        assert_eq!(session.viewport, Some(viewport));
    });
}

#[test]
fn fullscreen_shortcut_exits_but_escape_and_f11_reach_remote_keys() {
    let root = TestTempDir::new("nyaterm-fullscreen-shortcut");
    let mut cx = TestAppContext::single();
    let _cleanup = TestAppCleanup::new(&cx);
    let (app, _view, host) = fixture(&mut cx, root.path());
    connect_surface(&app, host, &mut cx);
    let mut visual = VisualTestContext::from_window(host.into(), &cx);
    visual.simulate_keystrokes("escape f11");
    app.update(&mut cx, |app, _| {
        assert!(app.has_remote_desktop_fullscreen());
        let session = app.remote_desktop.sessions.get_mut("remote").unwrap();
        for key in ["escape", "f11"] {
            assert!(
                session
                    .keys
                    .key_down(key, false)
                    .is_some_and(|event| matches!(
                        event,
                        nyaterm_remote_desktop::RdpInputEvent::KeyDown { repeat: true, .. }
                    )),
                "{key} was not forwarded"
            );
        }
    });
    visual.simulate_keystrokes("ctrl-shift-alt-f11");
    app.read_with(&cx, |app, _| {
        assert!(!app.has_remote_desktop_fullscreen());
        assert_eq!(
            app.remote_desktop.sessions["remote"].state,
            RemoteDesktopViewState::Connected
        );
    });
}

#[test]
fn toolbar_clock_hides_then_pointer_reveals_and_holds_it_open() {
    let root = TestTempDir::new("nyaterm-fullscreen-toolbar-clock");
    let mut cx = TestAppContext::single();
    let _cleanup = TestAppCleanup::new(&cx);
    let (_app, view, host) = fixture(&mut cx, root.path());
    cx.executor().advance_clock(INITIAL_DISPLAY);
    cx.run_until_parked();
    assert!(!view.read_with(&cx, |view, _| view.toolbar.visible));
    cx.update_window(host.into(), |_, window, cx| {
        let _ = window.draw(cx);
        window.dispatch_event(
            PlatformInput::MouseMove(MouseMoveEvent {
                position: point(window.viewport_size().width / 2., px(2.)),
                pressed_button: None,
                modifiers: Modifiers::default(),
            }),
            cx,
        );
    })
    .unwrap();
    cx.run_until_parked();
    assert!(view.read_with(&cx, |view, _| view.toolbar.visible));
    cx.executor().advance_clock(INITIAL_DISPLAY);
    cx.run_until_parked();
    assert!(view.read_with(&cx, |view, _| view.toolbar.visible));
    cx.update_window(host.into(), |_, window, cx| {
        window.dispatch_event(
            PlatformInput::MouseMove(MouseMoveEvent {
                position: point(px(10.), px(100.)),
                pressed_button: None,
                modifiers: Modifiers::default(),
            }),
            cx,
        );
    })
    .unwrap();
    cx.run_until_parked();
    cx.executor().advance_clock(HIDE_DELAY);
    cx.run_until_parked();
    assert!(!view.read_with(&cx, |view, _| view.toolbar.visible));
}

#[test]
fn exit_button_returns_disconnected_session_without_removing_it() {
    let root = TestTempDir::new("nyaterm-fullscreen-exit-button");
    let mut cx = TestAppContext::single();
    let _cleanup = TestAppCleanup::new(&cx);
    let (app, _view, host) = fixture(&mut cx, root.path());
    app.update(&mut cx, |app, _| {
        app.remote_desktop.sessions.get_mut("remote").unwrap().state =
            RemoteDesktopViewState::Disconnected;
    });
    cx.update_window(host.into(), |_, window, cx| {
        let _ = window.draw(cx);
        let position = point(window.viewport_size().width / 2., px(22.));
        window.dispatch_event(
            PlatformInput::MouseMove(MouseMoveEvent {
                position,
                pressed_button: None,
                modifiers: Modifiers::default(),
            }),
            cx,
        );
        window.dispatch_event(
            PlatformInput::MouseDown(MouseDownEvent {
                position,
                button: MouseButton::Left,
                modifiers: Modifiers::default(),
                click_count: 1,
                first_mouse: false,
            }),
            cx,
        );
        window.dispatch_event(
            PlatformInput::MouseUp(MouseUpEvent {
                position,
                button: MouseButton::Left,
                modifiers: Modifiers::default(),
                click_count: 1,
            }),
            cx,
        );
    })
    .unwrap();
    cx.run_until_parked();
    app.read_with(&cx, |app, _| {
        assert!(!app.has_remote_desktop_fullscreen());
        assert!(app.remote_desktop.fullscreen_window.is_none());
        assert_eq!(
            app.remote_desktop.sessions["remote"].state,
            RemoteDesktopViewState::Disconnected
        );
        assert!(app.session.metadata("remote").is_some());
    });
}

#[test]
fn stale_window_cannot_exit_a_new_fullscreen_window_for_the_same_session() {
    let root = TestTempDir::new("nyaterm-fullscreen-stale-window");
    let mut cx = TestAppContext::single();
    let _cleanup = TestAppCleanup::new(&cx);
    let (app, _view, old) = fixture(&mut cx, root.path());
    let replacement = cx.add_window(|window, cx| {
        let view = cx.new(|_| EmptyView);
        nyaterm_ui::nya_root(view, window, cx)
    });
    app.update(&mut cx, |app, cx| {
        app.remote_desktop.fullscreen_window = Some(replacement);
        app.exit_remote_desktop_fullscreen_from_window("remote", old.into(), cx);
        assert!(app.is_remote_desktop_fullscreen("remote"));
        assert_eq!(app.remote_desktop.fullscreen_window, Some(replacement));
        app.exit_remote_desktop_fullscreen_from_window("remote", replacement.into(), cx);
        assert!(!app.has_remote_desktop_fullscreen());
        assert!(app.remote_desktop.sessions.contains_key("remote"));
    });
}

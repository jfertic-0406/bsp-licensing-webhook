 // For now return it so YOU can test. Later you'll email this link.
    return res.json({ ok: true, downloadUrl });
  } catch (err) {
    console.error('🔥 /download/request error:', err);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});



















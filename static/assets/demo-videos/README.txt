STAGED CCTV FOOTAGE
===================
TRACE X never generates fake CCTV footage. Put your own staged clips here
(.mp4 recommended; .webm, .mov, .m4v, .ogv also accepted), then run:

    python -m database.seed --reset

Each video is registered as real evidence in CASE-001 (Riverside Library),
hashed with SHA-256, given camera IDs CAM-01, CAM-02 ... in file-name order,
and opens in the CCTV viewer.

You can also upload a video at any time from a case's Evidence Vault tab,
where you can enter the camera ID and the recording start time.

NOTE: --reset deletes the database, all uploaded evidence and all reports.
